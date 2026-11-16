"""Validate the supported compilation report before using its archived records."""
import re

from .compiler import compile_decisions, json_bytes
from .model import BridgeError, MAX_DECISIONS, fail, object_fields


_FIELDS = {"schemaVersion", "tool", "toolVersion", "source", "parameters", "decisions",
           "mappings", "losses", "counts", "openvexId", "omittedArtifacts", "artifacts", "warnings"}
_PARAMETERS = {"asOf", "author", "productId", "timestamp", "allowScopeLoss"}


def report_decision_document(report: object) -> dict:
    """Return validated records in report-array order, without changing indices.

    Reproduce the supported compiler's metadata and artifact hashes in memory.
    The original input cannot be recovered from normalized records, so its digest
    is checked for syntax and retained. Checking the original is a separate opt-in
    via verify_report_source; consistency alone does not verify that digest.
    No files are read/written and no saved artifact is applied.
    """
    try:
        root = object_fields(report, _FIELDS, _FIELDS, "report")
        if (type(root["schemaVersion"]) is not int or root["schemaVersion"] != 1
                or root["tool"] != "triage-bridge" or root["toolVersion"] != "0.1.0"):
            fail("E_REPORT", "unsupported report version or tool")
        source = object_fields(root["source"], {"schemaVersion", "canonicalJsonSha256"},
                               {"schemaVersion", "canonicalJsonSha256"}, "report source")
        if (type(source["schemaVersion"]) is not int or source["schemaVersion"] != 1
                or not isinstance(source["canonicalJsonSha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", source["canonicalJsonSha256"])):
            fail("E_REPORT", "invalid archived source metadata")
        params = object_fields(root["parameters"], _PARAMETERS, _PARAMETERS, "report parameters")
        rows = root["decisions"]
        if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_DECISIONS:
            fail("E_REPORT", "invalid report decisions")
        by_index = {}
        for row in rows:
            row = object_fields(row, {"index", "record"}, {"index", "record"}, "report decision")
            index = row["index"]
            if type(index) is not int or not 0 <= index < len(rows) or index in by_index:
                fail("E_REPORT", "invalid or duplicate archived decision index")
            by_index[index] = row["record"]
        # Every compiler report contains a complete zero-based index range.
        document = {"schemaVersion": 1, "decisions": [by_index[i] for i in range(len(rows))]}
        expected = compile_decisions(document, as_of=params["asOf"], author=params["author"],
                                     product_id=params["productId"], timestamp=params["timestamp"],
                                     allow_scope_loss=params["allowScopeLoss"]).report
        expected["source"] = source
        expected["decisions"] = [expected["decisions"][row["index"]] for row in rows]
        # Canonical bytes distinguish booleans/floats from integer metadata.
        # This also enforces normalized records and all nested field contracts.
        if json_bytes(expected) != json_bytes(root):
            fail("E_REPORT", "report metadata is inconsistent with archived decisions")
        return {"schemaVersion": 1, "decisions": [row["record"] for row in rows]}
    except (BridgeError, TypeError, ValueError, UnicodeError, RecursionError):
        fail("E_REPORT", "invalid or inconsistent conversion report; supported toolVersion is 0.1.0")


def verify_report_source(report: object, document: object) -> dict:
    """Match a decoded original v1 document to a validated archived compilation.

    Pure, explicit opt-in: no files are read or written. File callers should use
    load_document for bounded UTF-8/duplicate-key checks. Canonical input bytes
    follow compiler.json_bytes, before record normalization. Matching content is
    not authenticated origin, authorship or independent security evidence.
    """
    report_decision_document(report)
    try:
        params = report["parameters"]
        expected = compile_decisions(document, as_of=params["asOf"], author=params["author"],
                                     product_id=params["productId"], timestamp=params["timestamp"],
                                     allow_scope_loss=params["allowScopeLoss"]).report
        if (expected["source"] != report["source"]
                or len(expected["decisions"]) != len(report["decisions"])):
            fail("E_SOURCE", "original source does not match the archived compilation")
        # Array position in the report need not equal the original source index.
        indices = [row["index"] for row in report["decisions"]]
        expected["decisions"] = [expected["decisions"][i] for i in indices]
        if json_bytes(expected) != json_bytes(report):
            fail("E_SOURCE", "original source does not match the archived compilation")
        return {"status": "verified",
                "canonicalJsonSha256": expected["source"]["canonicalJsonSha256"],
                "decisionIndices": indices}
    except (BridgeError, TypeError, ValueError, UnicodeError, RecursionError):
        fail("E_SOURCE", "invalid original source or mismatch with archived compilation")
