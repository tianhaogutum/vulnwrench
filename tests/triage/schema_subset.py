"""Test-only evaluator for keywords in the checked-in OpenVEX schema.

Not a general JSON Schema library. Unrecognized assertion keywords fail closed.
Only formats exercised by this tool's emitted values are checked.
"""
from datetime import datetime
from pathlib import Path
import json
import re

SCHEMA_PATH = Path(__file__).resolve().parents[2] / "docs/triage/schemas/openvex-v0.2.0.schema.json"


def validate_openvex(document):
    root = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    annotations = {"$schema", "$id", "$defs", "title", "description"}
    supported = {"$ref", "type", "required", "properties", "additionalProperties", "enum", "const",
                 "minimum", "minItems", "uniqueItems", "items", "anyOf", "allOf", "if", "then", "format"}

    def matches(value, schema):
        try:
            check(value, schema)
            return True
        except AssertionError:
            return False

    def check(value, schema):
        unknown = set(schema) - annotations - supported
        if unknown:
            raise RuntimeError(f"test evaluator does not support schema keywords: {unknown}")
        if "$ref" in schema:
            ref = schema["$ref"]
            assert ref.startswith("#/$defs/")
            check(value, root["$defs"][ref.split("/")[-1]])
        if "type" in schema:
            types = {"object": dict, "array": list, "string": str, "integer": int}
            assert type(value) is types[schema["type"]], "wrong JSON type"
        if "enum" in schema:
            assert value in schema["enum"], "enum"
        if "const" in schema:
            assert value == schema["const"], "const"
        if "minimum" in schema:
            assert value >= schema["minimum"], "minimum"
        if "format" in schema:
            fmt = schema["format"]
            if fmt in {"uri", "iri"}:
                assert re.match(r"[A-Za-z][A-Za-z0-9+.-]*:.+", value) and not any(c.isspace() for c in value)
            elif fmt == "date-time":
                assert "T" in value and datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is not None
            else:
                raise RuntimeError("unsupported format in test evaluator")
        if isinstance(value, dict):
            assert set(schema.get("required", [])) <= set(value), "missing required fields"
            properties = schema.get("properties", {})
            if schema.get("additionalProperties") is False:
                assert not set(value) - set(properties), "unknown properties"
            for key in set(value) & set(properties):
                check(value[key], properties[key])
        if isinstance(value, list):
            assert len(value) >= schema.get("minItems", 0), "minItems"
            if schema.get("uniqueItems"):
                encoded = [json.dumps(v, sort_keys=True) for v in value]
                assert len(set(encoded)) == len(encoded), "uniqueItems"
            if "items" in schema:
                for item in value:
                    check(item, schema["items"])
        if "anyOf" in schema:
            assert any(matches(value, s) for s in schema["anyOf"]), "anyOf"
        for part in schema.get("allOf", []):
            check(value, part)
        if "if" in schema and matches(value, schema["if"]):
            check(value, schema["then"])

    check(document, root)
