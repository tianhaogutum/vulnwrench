"""Shared strict JSON boundary for local documents and exact config bytes."""

import json
import math

MAX_INPUT_BYTES = 32 * 1024 * 1024
MAX_JSON_DEPTH = 128  # Root container is level 1; scalars add no depth.


class InputError(ValueError):
    """Invalid or unsupported input; messages never include supplied values."""


def _check_metadata(value: dict, label: str) -> None:
    """Reject cycles/non-finite floats; shared completed containers remain valid."""
    active, completed = {id(value)}, set()
    stack = [(value, iter(value.values()))]
    while stack:
        node, children = stack[-1]
        try:
            child = next(children)
        except StopIteration:
            active.remove(id(node))
            completed.add(id(node))
            stack.pop()
            continue
        if isinstance(child, float) and not math.isfinite(child):
            raise InputError(f"{label}: non-finite numeric metadata")
        if not isinstance(child, (dict, list)):
            continue
        identity = id(child)
        if identity in active:
            raise InputError(f"{label}: cyclic object/array metadata")
        if identity not in completed:
            active.add(identity)
            stack.append((child, iter(child.values() if isinstance(child, dict) else child)))


def _pairs(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError("JSON contains duplicate object keys")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise InputError("JSON contains a non-finite numeric constant")


def _float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise InputError("JSON contains a non-finite numeric value")
    return number


def _check_depth(text: str, label: str) -> None:
    # Scan before recursive decoding/copying. JSON syntax remains json.loads' job;
    # only unquoted container delimiters count toward the raw-input depth bound.
    depth = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in '{[':
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise InputError(f"{label}: JSON nesting exceeds {MAX_JSON_DEPTH} levels")
        elif char in '}]':
            depth -= 1


def parse_json(raw: bytes, label: str) -> dict:
    if not isinstance(raw, bytes):
        raise InputError(f"{label}: expected raw config bytes")
    if len(raw) > MAX_INPUT_BYTES:
        raise InputError(f"{label}: input exceeds 32 MiB limit")
    try:
        text = raw.decode("utf-8")
        _check_depth(text, label)
        value = json.loads(text, object_pairs_hook=_pairs,
                           parse_constant=_constant, parse_float=_float)
    except InputError:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise InputError(f"{label}: invalid UTF-8 JSON") from None
    if not isinstance(value, dict):
        raise InputError(f"{label}: expected JSON object")
    return value
