"""Deterministic field projections with explicit, machine-readable losses."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from types import MappingProxyType
from typing import Mapping

from .model import (VEX_STATUSES, fail, parse_date, parse_decisions, parse_timestamp,
                    product_identifier, text)


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")


def digest(value: bytes) -> str:
    return sha256(value).hexdigest()


@dataclass(frozen=True)
class Compilation:
    """Immutable UTF-8 artifacts, including the conversion report."""
    files: Mapping[str, bytes]

    @property
    def report(self) -> dict:
        return json.loads(self.files["conversion-report.json"])


def compile_decisions(document: object, *, as_of: str, author: str,
                      product_id: str, timestamp: str,
                      allow_scope_loss: bool = False) -> Compilation:
    """Compile a validated snapshot; never writes files or executes processes.

    All records are requests for scanner suppression, even affected/investigating
    records. Only explicit VEX statuses become assertions, never accepted_risk.
    """
    decisions = parse_decisions(document)
    day = parse_date(as_of, "as-of")
    author = text(author, "author")
    product_id = product_identifier(product_id)
    timestamp = parse_timestamp(timestamp)
    if timestamp[:10] != day.isoformat():
        fail("E_DATE", "timestamp UTC date must equal as-of")
    if type(allow_scope_loss) is not bool:
        fail("E_INPUT", "allow_scope_loss must be a boolean")
    for i, decision in enumerate(decisions):
        if decision.expires_on <= day:
            fail("E_EXPIRED", f"decisions[{i}]: expired at as-of (expiresOn is the first invalid UTC day)")
    if not allow_scope_loss:
        fail("E_SCOPE_LOSS", "OSV IgnoredVulns cannot preserve package scope; review and explicitly use --allow-scope-loss")

    trivy = []
    osv: dict[str, dict] = {}
    statements = []
    mappings = []
    losses = []

    def loss(target, code, fields, indices, detail):
        losses.append({"target": target, "code": code, "fields": fields,
                       "decisionIndices": indices, "detail": detail})

    for i, decision in enumerate(decisions):
        rendered = []
        for vuln in decision.vulnerabilities:
            for id_ in vuln.expanded_ids:
                trivy.append({"id": id_, "purls": [decision.package],
                              "expired_at": decision.expires_on.isoformat(), "statement": decision.reason})
                row = {"id": id_, "reason": decision.reason,
                       "effectiveUntil": decision.expires_on.isoformat()}
                if id_ in osv and osv[id_] != row:
                    fail("E_CONFLICT", "OSV global projection has conflicting reasons or expiry dates across packages")
                osv[id_] = row
                rendered.append(id_)
            if decision.status in VEX_STATUSES:
                vulnerability = {"name": vuln.id}
                if vuln.aliases:
                    vulnerability["aliases"] = list(vuln.aliases)
                statement = {
                    "vulnerability": vulnerability,
                    "products": [{"@id": product_id, "subcomponents": [{"@id": decision.package}]}],
                    "status": decision.status,
                    "status_notes": (
                        f"Reason: {decision.reason}\nDecision owner: {decision.owner}\n"
                        f"Exception expiresOn (first invalid UTC day): {decision.expires_on.isoformat()}; "
                        "OpenVEX consumers do not enforce this expiry."
                    ),
                }
                for field in ("justification", "impact_statement", "action_statement"):
                    if getattr(decision, field) is not None:
                        statement[field] = getattr(decision, field)
                statements.append(statement)
        mappings.append({"decisionIndex": i, "package": decision.package,
                         "scannerIds": sorted(rendered),
                         "vexPrimaryIds": [v.id for v in decision.vulnerabilities]
                         if decision.status in VEX_STATUSES else []})
        loss("osv-scanner.toml", "package_scope_widened", ["package"], [i],
             "Authorized by --allow-scope-loss: IDs apply to every matching package in the OSV config scope.")
        if decision.status == "accepted_risk":
            loss("openvex.json", "no_vex_assertion", ["status"], [i],
                 "accepted_risk is an exception policy, not a VEX status; no statement emitted.")

    all_indices = list(range(len(decisions)))
    for target in (".trivyignore.yaml", "osv-scanner.toml"):
        loss(target, "decision_metadata_not_native", ["owner", "status", "justification", "impact_statement", "action_statement"],
             all_indices, "Scanner ignore formats cannot represent this decision metadata; retained in this report.")
    vex_indices = [i for i, d in enumerate(decisions) if d.status in VEX_STATUSES]
    if vex_indices:
        loss("openvex.json", "expiry_not_enforced", ["expiresOn"], vex_indices,
             "OpenVEX v0.2 has no native expiry; notes are informational. Regenerate and withdraw stale documents externally.")
        loss("openvex.json", "owner_not_structured", ["owner"], vex_indices,
             "Decision owner is preserved in status_notes, not a native structured field; author is the supplied document author.")
    for target, indices in ((".trivyignore.yaml", all_indices), ("osv-scanner.toml", all_indices),
                            ("openvex.json", vex_indices)):
        review_indices = [i for i in indices if decisions[i].decision_id is not None or decisions[i].source_refs]
        if review_indices:
            loss(target, "review_metadata_not_native", ["decisionId", "sourceRefs"], review_indices,
                 "Stable decision IDs and source references are retained in the conversion report, not projected into this target.")
    # Identical global entries may be merged, but all source records stay in report.
    if len(trivy) != len(osv):
        loss("osv-scanner.toml", "global_entries_coalesced", ["ids", "aliases"], all_indices,
             "Identical ID/reason/expiry projections from different packages share one IgnoredVulns entry.")

    trivy.sort(key=lambda row: (row["id"], row["purls"][0]))
    files = {".trivyignore.yaml": json_bytes({"vulnerabilities": trivy})}
    toml = ["# Generated by triage-bridge; inspect conversion-report.json before use.",
            "# Package scope was explicitly widened. This is scanner suppression, not VEX proof."]
    for id_ in sorted(osv):
        row = osv[id_]
        toml.extend(["", "[[IgnoredVulns]]", f"id = {json.dumps(id_, ensure_ascii=False)}",
                     f"reason = {json.dumps(row['reason'], ensure_ascii=False)}",
                     f"effectiveUntil = {row['effectiveUntil']}"])
    files["osv-scanner.toml"] = ("\n".join(toml) + "\n").encode("utf-8")
    vex_id = None
    if statements:
        statements.sort(key=lambda row: json_bytes(row))
        vex = {"@context": "https://openvex.dev/ns/v0.2.0", "author": author,
               "timestamp": timestamp, "version": 1, "tooling": "triage-bridge/0.1.0",
               "statements": statements}
        vex_id = "urn:sha256:" + digest(json_bytes(vex))
        vex["@id"] = vex_id
        files["openvex.json"] = json_bytes(vex)
    report = {
        "schemaVersion": 1, "tool": "triage-bridge", "toolVersion": "0.1.0",
        "source": {"canonicalJsonSha256": digest(json_bytes(document)), "schemaVersion": 1},
        "parameters": {"asOf": day.isoformat(), "author": author, "productId": product_id,
                       "timestamp": timestamp, "allowScopeLoss": allow_scope_loss},
        "decisions": [{"index": i, "record": d.as_record()} for i, d in enumerate(decisions)],
        "mappings": mappings, "losses": losses,
        "counts": {"decisions": len(decisions), "trivyEntries": len(trivy), "osvEntries": len(osv),
                   "vexStatements": len(statements)},
        "openvexId": vex_id,
        "omittedArtifacts": [] if statements else [{"file": "openvex.json", "reason": "No explicit VEX statuses; empty OpenVEX documents are invalid."}],
        "artifacts": {name: {"sha256": digest(data), "bytes": len(data)} for name, data in sorted(files.items())},
        "warnings": [
            "Every decision is compiled as a scanner ignore, including affected and under_investigation; this does not assert non-exploitability.",
            "Only supplied aliases are expanded here. OSV-Scanner may additionally suppress aliases using its own database.",
            "Expiry is date-only. The bridge rejects expiresOn <= asOf in UTC; native consumers control their runtime expiry behavior.",
            "No scanner, package, exploitability, alias truth, product membership, or author identity has been verified.",
        ],
    }
    files["conversion-report.json"] = json_bytes(report)
    return Compilation(MappingProxyType(files))
