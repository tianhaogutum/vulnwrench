"""Optional observational baseline view; never changes the current gate policy."""

from __future__ import annotations

from collections import defaultdict
import copy
import json

from .core import InputError, Policy, _array, _obj, _string, check_bytes

TOOL_FIELDS = ("name", "guid", "version", "semanticVersion")
NOTICE = ("Absent means not observed in these two reports under the selected fingerprint; "
          "it does not prove a vulnerability fixed or full scan coverage. Retained means identity "
          "matched, not that severity, message, location or suppression stayed unchanged. "
          "The comparison never changes the current gate decision.")


def _execution(report: dict) -> dict:
    totals = report["totals"]
    status = ("failed" if totals["failedInvocations"] or totals["errorNotifications"] else
              "unknown" if not report["runs"] or totals["unknownExecutionRuns"] else "successful")
    # Strict gate policy may also fail unknown execution. Keep actual failure
    # evidence distinct here, so a policy flag cannot turn unknown into failed.
    failures = []
    for failure in report["scanFailures"]:
        reasons = [r for r in failure["reasons"] if r in {"execution_unsuccessful", "tool_execution_error"}]
        if reasons:
            failures.append({"sourcePointer": failure["sourcePointer"], "reasons": reasons})
    return {"status": status, "scanFailures": failures,
            "unknownExecutionRuns": totals["unknownExecutionRuns"],
            "invocations": [{"sourcePointer": i["sourcePointer"],
                             "executionSuccessful": i["executionSuccessful"],
                             "notifications": i["notifications"]}
                            for run in report["runs"] for i in run["invocations"]]}


def _pairing(manifest: dict, reports: dict) -> tuple[dict, set[str]]:
    """Validate shape strictly, but preserve uncertain correspondence as ambiguity."""
    _obj(manifest, "runPairing")
    if set(manifest) not in ({"baseline", "current"}, {"baseline", "current", "inputSha256"}):
        raise InputError("runPairing: expected baseline/current arrays and optional inputSha256 only")
    assignments = {}
    issues = set()
    for side, report in reports.items():
        runs, labels = {}, set()
        for index, value in enumerate(_array(manifest[side], "runPairing/" + side)):
            path = f"runPairing/{side}/{index}"
            entry = _obj(value, path)
            if set(entry) != {"runIndex", "pairId"}:
                raise InputError(path + ": expected runIndex and pairId only")
            ri = entry["runIndex"]
            if type(ri) is not int or not 0 <= ri < len(report["runs"]):
                raise InputError(path + "/runIndex: expected in-range integer")
            label = _string(entry["pairId"], path + "/pairId")
            if ri in runs:
                issues.add("run_pairing_duplicate_run")
            if label in labels:
                issues.add("run_pairing_duplicate_pair_id")
            runs[ri] = label
            labels.add(label)
        if set(runs) != set(range(len(report["runs"]))):
            issues.add("run_pairing_incomplete")
        assignments[side] = runs
    if set(assignments["baseline"].values()) != set(assignments["current"].values()):
        issues.add("run_pairing_unpaired_id")
    if "inputSha256" in manifest:
        digests = _obj(manifest["inputSha256"], "runPairing/inputSha256")
        if set(digests) != {"baseline", "current"}:
            raise InputError("runPairing/inputSha256: expected baseline and current digests only")
        for side, report in reports.items():
            digest = digests[side]
            if (not isinstance(digest, str) or len(digest) != 64
                    or any(char not in "0123456789abcdef" for char in digest)):
                raise InputError("runPairing/inputSha256/" + side + ": expected 64 lowercase hex characters")
            # check_bytes evidence hashes the exact supplied bytes, including stdin.
            if digest != report["evidence"]["sha256"]:
                issues.add("run_pairing_input_digest_mismatch")
    return assignments, issues


def _inventory(report: dict, fingerprint: str, assignments: dict | None = None) -> dict:
    """Validate only newly consumed fields. No location/message fallback identity."""
    tools = {}
    run_groups = {}
    extension_identities = {}
    for ri, run in enumerate(report["evidence"]["document"]["runs"]):
        path = f"/runs/{ri}"
        driver = run["tool"]["driver"]
        identity = {field: _string(driver[field], path + "/tool/driver/" + field)
                    for field in TOOL_FIELDS if field in driver}
        extension_identities[ri] = [
            {field: _string(component[field], f"{path}/tool/extensions/{ci}/{field}")
             for field in TOOL_FIELDS if field in component}
            for ci, component in enumerate(run["tool"].get("extensions", []))]
        pair_id = assignments[ri] if assignments is not None else None
        key = json.dumps([pair_id, identity] if assignments is not None else identity, sort_keys=True)
        group = tools.setdefault(key, {"identity": identity, "runs": [], "records": [], "issues": set()})
        if assignments is not None:
            group["pairId"] = pair_id
        run_groups[ri] = group
        group["runs"].append(ri)
        if "results" not in run:
            group["issues"].add("results_missing")
    for trace in report["results"]:
        ri, rsi = trace["runIndex"], trace["resultIndex"]
        run = report["evidence"]["document"]["runs"][ri]
        group = run_groups[ri]
        result = run["results"][rsi]
        path = trace["sourcePointer"]
        fingerprints = _obj(result.get("fingerprints", {}), path + "/fingerprints")
        for value in fingerprints.values():
            # Do not echo user-controlled fingerprint names in diagnostics.
            _string(value, path + "/fingerprints/value")
        value = fingerprints.get(fingerprint)
        if value is None:
            group["issues"].add("fingerprint_missing")
        rule = {"id": trace["ruleId"]}
        if trace["ruleId"] is None:
            group["issues"].add("rule_identity_missing")
        component_trace = trace["ruleComponent"]
        component = run["tool"]["driver"]
        if component_trace["kind"] == "extension":
            ci = component_trace["index"]
            component = run["tool"]["extensions"][ci]
            identity = extension_identities[ri][ci]
            rule["toolComponent"] = identity
            # Equal metadata cannot establish which same-named pack is which
            # after reordering. Never use array position as stable identity.
            if extension_identities[ri].count(identity) > 1:
                group["issues"].add("rule_component_identity_ambiguous")
        if trace["ruleIndex"] is not None:
            descriptor = component["rules"][trace["ruleIndex"]]
            if "guid" in descriptor:
                rule["guid"] = _string(descriptor["guid"], trace["ruleSourcePointer"] + "/guid")
        if trace["baselineState"] == "absent":
            group["issues"].add("report_marks_absent")
        group["records"].append({"fingerprint": value, "trace": {**trace, "ruleIdentity": rule}})
    return tools


def compare_bytes(current_data: bytes, baseline_data: bytes, *, fingerprint: str,
                  policy: Policy | None = None, run_pairing: dict | None = None) -> dict:
    """Return the current gate report plus an optional, conservative baseline view.

    Use exactly one explicit result.fingerprints key. Both inputs must satisfy
    the supported SARIF subset. Malformed fields raise InputError. Uncertain
    identities/evidence remain visible as ambiguous entries, never resolved.
    Optional run_pairing declares per-side {runIndex, pairId} assignments. Every
    run and pair ID must be unique and complete on both sides; uncertainty in
    the manifest taints the entire view without applying any assignments.
    Optional inputSha256 binds both sides to their exact input-byte SHA-256
    digests; a mismatch also prevents all assignments and classifications.
    """
    _string(fingerprint, "comparison.fingerprint")
    current = check_bytes(current_data, policy)
    baseline = check_bytes(baseline_data)
    reports = {"baseline": baseline, "current": current}
    assignments, pairing_issues = ({}, set()) if run_pairing is None else _pairing(run_pairing, reports)
    inventories = {side: _inventory(report, fingerprint, assignments.get(side) if not pairing_issues else None)
                   for side, report in reports.items()}
    execution = {side: _execution(report) for side, report in reports.items()}
    global_issues = set(pairing_issues)
    for side, report in reports.items():
        if execution[side]["status"] != "successful":
            global_issues.add(side + "_execution_" + execution[side]["status"])
        if not report["runs"]:
            global_issues.add(side + "_no_runs")
        if any(not run["resultsPresent"] for run in report["runs"]):
            global_issues.add(side + "_results_missing")
    issues = set(global_issues)
    entries = []
    counts = dict.fromkeys(("newly_observed", "retained", "absent", "ambiguous"), 0)
    for tool_key in sorted(inventories["baseline"].keys() | inventories["current"].keys()):
        groups = {side: inventory.get(tool_key) for side, inventory in inventories.items()}
        reasons = set(global_issues)
        if any(group is None for group in groups.values()):
            reasons.add("tool_identity_unpaired")
        if any(group and len(group["runs"]) > 1 for group in groups.values()):
            reasons.add("tool_run_collision")
        for group in groups.values():
            if group:
                reasons.update(group["issues"])
        # An unidentified result could be any unmatched finding. Taint the whole
        # tool-run pair instead of falsely calling a counterpart new or absent.
        buckets = defaultdict(lambda: {"baseline": [], "current": []})
        for side, group in groups.items():
            for record in group["records"] if group else []:
                buckets[record["fingerprint"]][side].append(record["trace"])
        issues.update(reasons)
        for value in sorted(buckets, key=lambda v: (v is not None, v or "")):
            pair = buckets[value]
            entry_reasons = set(reasons)
            if any(len(records) > 1 for records in pair.values()):
                entry_reasons.add("fingerprint_collision")
            if (len(pair["baseline"]) == len(pair["current"]) == 1
                    and pair["baseline"][0]["ruleIdentity"] != pair["current"][0]["ruleIdentity"]):
                entry_reasons.add("rule_identity_changed")
            state = ("ambiguous" if entry_reasons else "retained" if all(pair.values()) else
                     "newly_observed" if pair["current"] else "absent")
            counts[state] += 1
            issues.update(entry_reasons)
            identity = next(group["identity"] for group in groups.values() if group)
            entry = {"state": state, "fingerprint": value, "toolIdentity": identity,
                     "reasons": sorted(entry_reasons), **pair}
            if run_pairing is not None:
                entry["pairId"] = next((group["pairId"] for group in groups.values()
                                        if group and "pairId" in group), None)
            entries.append(entry)
    status = ("invalid" if any(e["status"] == "failed" for e in execution.values()) else
              "ambiguous" if issues else "compared")
    current["baselineComparison"] = {"status": status, "fingerprintKey": fingerprint,
                                     "counts": counts, "issues": sorted(issues), "entries": entries,
                                     "execution": execution, "baselineEvidence": baseline["evidence"],
                                     "notice": NOTICE}
    if run_pairing is not None:
        current["baselineComparison"]["runPairing"] = {"document": copy.deepcopy(run_pairing),
                                                      "applied": not pairing_issues}
    return current
