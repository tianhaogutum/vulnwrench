"""Offline, evidence-only attribution of Trivy image vulnerability findings."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import re
from typing import Any

from ._inputs import InputError, MAX_INPUT_BYTES, _check_metadata, parse_json


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MANIFEST_TYPE = "application/vnd.oci.image.manifest.v1+json"
_CONFIG_TYPE = "application/vnd.oci.image.config.v1+json"
_LAYER_TYPES = {f"application/vnd.oci.image.layer.{kind}.tar{compression}"
                for kind in ("v1", "nondistributable.v1")
                for compression in ("", "+gzip", "+zstd")}


def _object(value: Any, context: str) -> dict:
    if not isinstance(value, dict) or any(not isinstance(k, str) for k in value):
        raise InputError(f"{context}: expected JSON object")
    return value


def _digest(value: Any, context: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise InputError(f"{context}: expected lowercase sha256 with 64 hexadecimal digits")
    return value


def _string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise InputError(f"{context}: expected nonempty string")
    return value


def _diff_ids(config: dict, context: str) -> list[str]:
    rootfs = _object(config.get("rootfs"), f"{context}.rootfs")
    if rootfs.get("type") != "layers":
        raise InputError(f"{context}.rootfs.type: only layers is supported")
    values = rootfs.get("diff_ids")
    if not isinstance(values, list):
        raise InputError(f"{context}.rootfs.diff_ids: expected array")
    return [_digest(v, f"{context}.rootfs.diff_ids[{i}]") for i, v in enumerate(values)]


def _history(config: dict, count: int, source: str, warnings: list[dict]) -> list[dict]:
    """Never guess positions if history cannot be aligned in its entirety."""
    unknown = [{"layerIndex": i, "historyIndex": None, "createdBy": None} for i in range(count)]
    history = config.get("history")
    if history is None:
        warnings.append({"code": "history_missing", "source": source})
        return unknown
    if not isinstance(history, list):
        raise InputError(f"{source}.history: expected array")
    aligned = []
    for i, entry in enumerate(history):
        entry = _object(entry, f"{source}.history[{i}]")
        if "empty_layer" in entry and not isinstance(entry["empty_layer"], bool):
            raise InputError(f"{source}.history[{i}].empty_layer: expected boolean")
        if "created_by" in entry and not isinstance(entry["created_by"], str):
            raise InputError(f"{source}.history[{i}].created_by: expected string")
        if not entry.get("empty_layer", False):
            aligned.append({"layerIndex": len(aligned), "historyIndex": i,
                            "createdBy": entry.get("created_by")})
    if len(aligned) != count:
        warnings.append({"code": "history_count_mismatch", "source": source,
                         "diffIdCount": count, "nonEmptyHistoryCount": len(aligned)})
        return unknown
    if any(item["createdBy"] is None for item in aligned):
        warnings.append({"code": "history_command_missing", "source": source})
    return aligned


def _validate_report(report: dict) -> list[dict]:
    if type(report.get("SchemaVersion")) is not int or report["SchemaVersion"] != 2:
        raise InputError("report.SchemaVersion: only Trivy JSON schema 2 is supported")
    if report.get("ArtifactType") != "container_image":
        raise InputError("report.ArtifactType: only container_image is supported")
    results = report.get("Results")
    if results is None:
        return []
    if not isinstance(results, list):
        raise InputError("report.Results: expected array or null")
    for i, result in enumerate(results):
        context = f"report.Results[{i}]"
        _object(result, context)
        _string(result.get("Target"), f"{context}.Target")
        # These are different scanner finding families, not vulnerabilities.
        for family in ("Secrets", "Misconfigurations", "Licenses", "CustomResources"):
            entries = result.get(family)
            if entries is not None and not isinstance(entries, list):
                raise InputError(f"{context}.{family}: expected array or null")
            if entries:
                raise InputError(f"{context}.{family}: unsupported finding family")
        vulns = result.get("Vulnerabilities")
        if vulns is None:
            continue
        if not isinstance(vulns, list):
            raise InputError(f"{context}.Vulnerabilities: expected array or null")
        for j, finding in enumerate(vulns):
            path = f"{context}.Vulnerabilities[{j}]"
            _object(finding, path)
            for field in ("VulnerabilityID", "PkgName"):
                _string(finding.get(field), f"{path}.{field}")
            layer = finding.get("Layer")
            if layer is not None:
                _object(layer, f"{path}.Layer")
                for field in ("DiffID", "Digest"):
                    if field in layer and layer[field] != "":
                        _digest(layer[field], f"{path}.Layer.{field}")
    return results


def _report_binding(report: dict, image_ids: list[str], warnings: list[dict]) -> str:
    metadata = report.get("Metadata")
    if metadata is None:
        metadata = {}
    _object(metadata, "report.Metadata")
    sequences = []
    if "DiffIDs" in metadata:
        values = metadata["DiffIDs"]
        if not isinstance(values, list):
            raise InputError("report.Metadata.DiffIDs: expected array")
        sequences.append([_digest(v, "report.Metadata.DiffIDs entry") for v in values])
    if metadata.get("ImageConfig") is not None:
        config = _object(metadata["ImageConfig"], "report.Metadata.ImageConfig")
        if "rootfs" in config:
            sequences.append(_diff_ids(config, "report.Metadata.ImageConfig"))
    if not sequences:
        warnings.append({"code": "report_config_binding_unverified", "source": "report"})
        return "unverified"
    if any(ids != image_ids for ids in sequences):
        warnings.append({"code": "report_config_diff_ids_mismatch", "source": "report"})
        return "mismatch"
    return "diff_ids_consistent"


def _descriptor(value: Any, context: str, media_types: set[str]) -> dict:
    descriptor = _object(value, context)
    if not isinstance(descriptor.get("mediaType"), str) or descriptor["mediaType"] not in media_types:
        raise InputError(f"{context}.mediaType: unsupported media type")
    _digest(descriptor.get("digest"), f"{context}.digest")
    size = descriptor.get("size")
    if type(size) is not int or not 0 <= size < 2**63:
        raise InputError(f"{context}.size: expected nonnegative int64")
    return descriptor


def _manifest_config(manifest: dict, raw: bytes, source: str = "image") -> dict:
    """Verify config bytes before parsing; never read descriptor URLs or blob data."""
    context = source + "_manifest"
    _object(manifest, context)
    if type(manifest.get("schemaVersion")) is not int or manifest["schemaVersion"] != 2:
        raise InputError(f"{context}.schemaVersion: only OCI schema 2 is supported")
    if manifest.get("mediaType", _MANIFEST_TYPE) != _MANIFEST_TYPE:
        raise InputError(f"{context}.mediaType: only OCI image manifests are supported")
    config = _descriptor(manifest.get("config"), f"{context}.config", {_CONFIG_TYPE})
    if not isinstance(raw, bytes):
        raise InputError(f"{context}: verification requires raw config bytes")
    if len(raw) > MAX_INPUT_BYTES:
        raise InputError(f"{source} config: input exceeds 32 MiB limit")
    if len(raw) != config["size"]:
        raise InputError(f"{context}: config size mismatch")
    if "sha256:" + hashlib.sha256(raw).hexdigest() != config["digest"]:
        raise InputError(f"{context}: config digest mismatch")
    return parse_json(raw, source + " config")


def _pinned_config(raw: bytes, pin: str, source: str) -> None:
    """Check original bytes; leave parsing until any manifest hash/size checks pass."""
    context = source + "_config"
    _digest(pin, context + "_sha256")
    if raw is None:
        raise InputError(f"{context}_sha256: requires {context}")
    if not isinstance(raw, bytes):
        raise InputError(f"{context}_sha256: verification requires raw config bytes")
    if len(raw) > MAX_INPUT_BYTES:
        raise InputError(f"{source} config: input exceeds 32 MiB limit")
    if "sha256:" + hashlib.sha256(raw).hexdigest() != pin:
        raise InputError(f"{context}: config digest mismatch")


def _pinned_manifest(manifest: bytes, pin: str, source: str) -> dict:
    """Check the caller's local byte pin before interpreting any manifest JSON."""
    context = source + "_manifest"
    _digest(pin, context + "_sha256")
    if manifest is None:
        raise InputError(f"{context}_sha256: requires {context}")
    if not isinstance(manifest, bytes):
        raise InputError(f"{context}_sha256: verification requires raw manifest bytes")
    if len(manifest) > MAX_INPUT_BYTES:
        raise InputError(f"{source} manifest: input exceeds 32 MiB limit")
    if "sha256:" + hashlib.sha256(manifest).hexdigest() != pin:
        raise InputError(f"{context}: manifest digest mismatch")
    return parse_json(manifest, source + " manifest")


def _pinned_report(report: bytes, pin: str) -> dict:
    """Check exact local report bytes before parsing or interpreting evidence."""
    _digest(pin, "report_sha256")
    if report is None:
        raise InputError("report_sha256: requires report")
    if not isinstance(report, bytes):
        raise InputError("report_sha256: verification requires raw report bytes")
    if len(report) > MAX_INPUT_BYTES:
        raise InputError("report: input exceeds 32 MiB limit")
    if "sha256:" + hashlib.sha256(report).hexdigest() != pin:
        raise InputError("report: report digest mismatch")
    return parse_json(report, "report")


def _pinned_digest_map(mapping: bytes, pin: str, source: str = "image") -> dict:
    """Bind exact caller-local map bytes before interpreting the assertion map."""
    context = "base_digest_map" if source == "base" else "digest_map"
    label = "base digest map" if source == "base" else "digest map"
    _digest(pin, context + "_sha256")
    if mapping is None:
        raise InputError(f"{context}_sha256: requires {context}")
    if not isinstance(mapping, bytes):
        raise InputError(f"{context}_sha256: verification requires raw digest map bytes")
    if len(mapping) > MAX_INPUT_BYTES:
        raise InputError(f"{label}: input exceeds 32 MiB limit")
    if "sha256:" + hashlib.sha256(mapping).hexdigest() != pin:
        raise InputError(f"{context}: digest map digest mismatch")
    return parse_json(mapping, label)


def _mapping(value: dict | None, ids: list[str], context: str, source: str) -> dict:
    mapping = {} if value is None else _object(value, context)
    for compressed, diff_id in mapping.items():
        _digest(compressed, f"{context} key")
        _digest(diff_id, f"{context} value")
        if diff_id not in ids:
            raise InputError(f"{context} value: DiffID is absent from {source} rootfs")
    return mapping


def _manifest_layers(manifest: dict, ids: list[str], mapping: dict,
                     source: str = "image") -> dict:
    context = source + "_manifest"
    map_context = "base_digest_map" if source == "base" else "digest_map"
    layers = manifest.get("layers")
    if not isinstance(layers, list):
        raise InputError(f"{context}.layers: expected array")
    if len(layers) != len(ids):
        raise InputError(f"{context}: layer count mismatch")
    digests = set()
    for i, (layer, diff_id) in enumerate(zip(layers, ids)):
        descriptor = _descriptor(layer, f"{context}.layers[{i}]", _LAYER_TYPES)
        digest = descriptor["digest"]
        digests.add(digest)
        if digest not in mapping:
            raise InputError(f"{context}: missing layer mapping")
        if mapping[digest] != diff_id:
            raise InputError(f"{context}: ordered layer mapping mismatch")
    if mapping.keys() - digests:
        raise InputError(f"{map_context} key: Digest is absent from manifest")
    return {"status": "verified_local", "configDigest": manifest["config"]["digest"],
            "orderedLayerCount": len(layers), "layerContentVerified": False}


def explain(report: dict | bytes, base_config: dict | bytes, image_config: dict | bytes, *,
            digest_map: dict | bytes | None = None, gate: str = "none",
            image_manifest: dict | bytes | None = None, base_manifest: dict | bytes | None = None,
            base_digest_map: dict | bytes | None = None, base_manifest_sha256: str | None = None,
            image_manifest_sha256: str | None = None, report_sha256: str | None = None,
            digest_map_sha256: str | None = None, base_digest_map_sha256: str | None = None,
            base_config_sha256: str | None = None, image_config_sha256: str | None = None) -> dict:
    """Return deterministic JSON-compatible groups, preserving every input finding.

    ``gate`` is ``none``, ``app`` (app + unknown fail), or ``all`` (any fail).
    An explicit Digest->DiffID map is caller evidence, never inferred from position.
    With image_manifest, image_config must be exact raw bytes: config hash/size and
    every ordered descriptor mapping are checked. Layer content is not verified.
    With base_manifest, base_config must likewise be exact bytes; base_digest_map
    binds only its ordered descriptors and never supplies finding evidence.
    With base_manifest_sha256 or image_manifest_sha256, the corresponding manifest
    must be exact bytes; verify each pin before strict parsing of that manifest.
    Pin agreement is local, not proof of authenticity.
    With report_sha256, report must be exact bounded bytes; hash before strict
    parsing and preserve the parsed report with local pin agreement in provenance.
    With digest_map_sha256, digest_map must be bounded immutable bytes; verify its
    hash before strict map parsing. The parsed map still requires all evidence checks.
    base_digest_map_sha256 independently pins base map bytes with the same contract.
    A pinned base map still requires a base manifest and never supplies finding evidence.
    With base_config_sha256 or image_config_sha256, the corresponding config must
    be bounded immutable original bytes; hash before parsing, retaining any
    independent manifest config size/hash checks.
    A config pin alone establishes no manifest binding or layer-content verification.
    The base binding is verified before checking the exact-prefix boundary.
    Other inputs are JSON-compatible dictionaries. No files, network or commands used.
    Cyclic metadata and non-finite floats reject before copying; shared acyclic values remain.
    """
    if gate not in ("none", "app", "all"):
        raise InputError("gate: expected none, app, or all")
    if report_sha256 is not None:
        report = _pinned_report(report, report_sha256)
    report = _object(report, "report")
    if base_manifest_sha256 is not None:
        base_manifest = _pinned_manifest(base_manifest, base_manifest_sha256, "base")
    if image_manifest_sha256 is not None:
        image_manifest = _pinned_manifest(image_manifest, image_manifest_sha256, "image")
    if digest_map_sha256 is not None:
        digest_map = _pinned_digest_map(digest_map, digest_map_sha256)
    if base_digest_map_sha256 is not None:
        base_digest_map = _pinned_digest_map(base_digest_map, base_digest_map_sha256, "base")
    if base_digest_map is not None and base_manifest is None:
        raise InputError("base_digest_map: requires base_manifest")
    if base_config_sha256 is not None:
        _pinned_config(base_config, base_config_sha256, "base")
    if base_manifest is not None:
        base_config = _manifest_config(base_manifest, base_config, "base")
    elif base_config_sha256 is not None:
        base_config = parse_json(base_config, "base config")
    base_config = _object(base_config, "base")
    if image_config_sha256 is not None:
        _pinned_config(image_config, image_config_sha256, "image")
    if image_manifest is not None:
        image_config = _manifest_config(image_manifest, image_config)
    elif image_config_sha256 is not None:
        image_config = parse_json(image_config, "image config")
    image_config = _object(image_config, "image")
    # Normalize raw inputs and finish their size/hash/parse checks first. Walk all
    # retained documents before copying any finding or provenance from callers.
    for document, label in ((report, "report"), (base_config, "base config"),
                            (image_config, "image config"), (base_manifest, "base manifest"),
                            (image_manifest, "image manifest")):
        if document is not None:
            _check_metadata(document, label)
    base_ids = _diff_ids(base_config, "base")
    image_ids = _diff_ids(image_config, "image")
    base_manifest_binding = None
    if base_manifest is not None:
        base_mapping = _mapping(base_digest_map, base_ids, "base_digest_map", "base")
        base_manifest_binding = _manifest_layers(base_manifest, base_ids, base_mapping, "base")
        if base_manifest_sha256 is not None:
            base_manifest_binding.update(manifestDigest=base_manifest_sha256,
                                         manifestPinAgreement="matched_local")
    if len(base_ids) > len(image_ids) or base_ids != image_ids[:len(base_ids)]:
        raise InputError("base ancestry: base diff_ids must be an exact prefix of image diff_ids")
    results = _validate_report(report)
    warnings: list[dict] = []
    base_history = _history(base_config, len(base_ids), "base", warnings)
    image_history = _history(image_config, len(image_ids), "image", warnings)
    if any(b["createdBy"] != f["createdBy"] for b, f in zip(base_history, image_history)):
        warnings.append({"code": "base_image_history_commands_differ", "source": "configs"})
    binding = _report_binding(report, image_ids, warnings)
    mapping = _mapping(digest_map, image_ids, "digest_map", "image")
    if base_manifest_binding is not None and any(
            mapping[digest] != diff_id for digest, diff_id in base_mapping.items() if digest in mapping):
        raise InputError("base_digest_map: conflicts with digest_map")
    manifest_binding = None
    if image_manifest is not None:
        manifest_binding = _manifest_layers(image_manifest, image_ids, mapping)
        if image_manifest_sha256 is not None:
            manifest_binding.update(manifestDigest=image_manifest_sha256,
                                    manifestPinAgreement="matched_local")
    indices: dict[str, list[int]] = {}
    for i, diff_id in enumerate(image_ids):
        indices.setdefault(diff_id, []).append(i)
    groups: dict[str, list[dict]] = {"base": [], "app": [], "unknown": []}
    for i, result in enumerate(results):
        for j, finding in enumerate(result.get("Vulnerabilities") or []):
            layer = finding.get("Layer") or {}
            direct = layer.get("DiffID") or None
            compressed = layer.get("Digest") or None
            mapped = mapping.get(compressed)
            diff_id = direct or mapped
            proof = "exact_diff_id" if direct else "explicit_digest_mapping"
            reason = None
            matches = indices.get(diff_id, [])
            if binding == "mismatch":
                reason = "report_config_mismatch"
            elif direct and mapped and direct != mapped:
                reason = "conflicting_layer_evidence"
            elif diff_id is None:
                reason = "unmapped_compressed_digest" if compressed else "missing_layer_evidence"
            elif not matches:
                reason = "diff_id_not_in_image"
            elif any(k < len(base_ids) for k in matches) and any(k >= len(base_ids) for k in matches):
                reason = "diff_id_crosses_base_boundary"
            origin = "unknown" if reason else ("base" if matches[0] < len(base_ids) else "app")
            attribution = {
                "origin": origin, "proof": "unknown" if reason else proof,
                "reason": reason, "diffId": diff_id, "digest": compressed,
                "layerIndices": matches,
                "history": [deepcopy(image_history[k]) for k in matches],
                "warnings": ["repeated_diff_id"] if len(matches) > 1 else [],
                "source": {"resultIndex": i, "findingIndex": j, "target": result["Target"]},
                "finding": deepcopy(finding),
            }
            groups[origin].append(attribution)
    counts = {origin: len(items) for origin, items in groups.items()}
    failed = (counts["app"] + counts["unknown"] if gate == "app" else
              sum(counts.values()) if gate == "all" else 0)
    output = {
        "schemaVersion": 1,
        "ancestry": {"verifiedPrefix": True, "baseLayerCount": len(base_ids),
                     "imageLayerCount": len(image_ids), "reportConfigBinding": binding},
        "counts": {**counts, "total": sum(counts.values())},
        "gate": {"mode": gate, "status": "disabled" if gate == "none" else
                 "failed" if failed else "passed", "blockingFindings": failed},
        "groups": groups, "warnings": warnings,
        "provenance": {"report": deepcopy(report), "baseConfig": deepcopy(base_config),
                       "imageConfig": deepcopy(image_config), "digestMap": deepcopy(mapping)},
    }
    if base_config_sha256 is not None:
        output["provenance"].update(baseConfigDigest=base_config_sha256,
                                    baseConfigPinAgreement="matched_local")
    if image_config_sha256 is not None:
        output["provenance"].update(imageConfigDigest=image_config_sha256,
                                    imageConfigPinAgreement="matched_local")
    if report_sha256 is not None:
        output["provenance"].update(reportDigest=report_sha256, reportPinAgreement="matched_local")
    if digest_map_sha256 is not None:
        output["provenance"].update(digestMapDigest=digest_map_sha256,
                                    digestMapPinAgreement="matched_local")
    if base_digest_map_sha256 is not None:
        output["provenance"].update(baseDigestMapDigest=base_digest_map_sha256,
                                    baseDigestMapPinAgreement="matched_local")
    if base_manifest_binding is not None:
        output["ancestry"]["baseManifestBinding"] = base_manifest_binding
        output["provenance"]["baseManifest"] = deepcopy(base_manifest)
        output["provenance"]["baseDigestMap"] = deepcopy(base_mapping)
    if manifest_binding is not None:
        output["ancestry"]["imageManifestBinding"] = manifest_binding
        output["provenance"]["imageManifest"] = deepcopy(image_manifest)
    return output
