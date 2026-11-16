"""Conservative, bounded package identities, independently implemented."""

import re
from urllib.parse import quote, unquote


class InputError(ValueError):
    """Invalid or unsupported input. Messages contain no input values."""


# Deliberately finite: unknown ecosystems are isolated, never guessed from names.
ECOSYSTEMS = {
    "npm": "npm", "node-pkg": "npm", "javascript": "npm",
    "pypi": "pypi", "python": "pypi", "python-pkg": "pypi",
    "maven": "maven", "java": "maven", "java-archive": "maven", "jar": "maven",
    "go": "golang", "golang": "golang", "go-module": "golang",
    "gomod": "golang", "gobinary": "golang",
    "rubygems": "gem", "ruby": "gem", "gem": "gem", "gemspec": "gem",
    "crates.io": "cargo", "rust": "cargo", "cargo": "cargo",
    "nuget": "nuget", "dotnet": "nuget",
    "deb": "deb", "debian": "deb", "rpm": "rpm", "apk": "apk", "alpine": "apk",
}
PURL_TYPES = frozenset(ECOSYSTEMS.values())
# OS packages require an explicit PURL (distribution namespace/qualifiers matter).
FALLBACK_TYPES = PURL_TYPES - {"deb", "rpm", "apk"}


def text(value, *, optional=False):
    if value is None and optional:
        return None
    if not isinstance(value, str) or not value or value != value.strip():
        raise InputError("expected a nonempty string without surrounding whitespace")
    if any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value):
        raise InputError("control characters or invalid Unicode are unsupported")
    return value


def token(value):
    value = text(value)
    if any(c.isspace() for c in value):
        raise InputError("whitespace in package identity or installed version is unsupported")
    return value


def ecosystem(value):
    if value is None:
        return None
    return ECOSYSTEMS.get(text(value).lower())


def _decode(value):
    if re.search(r"%(?![0-9a-fA-F]{2})", value):
        raise InputError("invalid PURL percent escape")
    try:
        return token(unquote(value, encoding="utf-8", errors="strict"))
    except UnicodeError:
        raise InputError("invalid PURL encoding") from None


def _encode(value):
    return quote(value, safe=".-_~")


def _normalize(kind, namespace, name):
    if kind == "pypi":
        name = re.sub(r"[-_.]+", "-", name).lower()
    elif kind in {"npm", "nuget"}:
        name = name.lower()
        namespace = namespace.lower()
    return namespace, name


def _shape(kind, namespace, name):
    if namespace and any(part in {"", ".", ".."} for part in namespace.split("/")):
        raise InputError("unsupported package namespace segment")
    if kind in {"pypi", "gem", "cargo", "nuget"} and namespace:
        raise InputError("namespace is unsupported for this PURL type")
    if kind == "maven" and not namespace:
        raise InputError("Maven group namespace is required")
    if kind == "npm" and namespace and ("/" in namespace or not namespace.startswith("@") or len(namespace) == 1):
        raise InputError("unsupported npm scope")
    if name in {".", ".."}:
        raise InputError("unsupported package name")


def _check_reported_name(reported, parts):
    if reported is None:
        return
    _, normalized = _normalize(parts["type"], "", reported)
    allowed = {parts["name"]}
    if parts["namespace"]:
        allowed.add(parts["namespace"] + "/" + parts["name"])
        if parts["type"] == "maven":
            allowed.add(parts["namespace"] + ":" + parts["name"])
    if normalized not in allowed:
        raise InputError("reported package name contradicts PURL identity")


def parse_purl(value):
    """Parse a strict supported PURL syntax subset; retain qualifiers/subpath."""
    value = token(value)
    if not value.startswith("pkg:") or value.count("#") > 1 or value.count("?") > 1:
        raise InputError("invalid PURL structure")
    main, _, fragment = value[4:].partition("#")
    main, query_marker, query = main.partition("?")
    kind, slash, path = main.partition("/")
    if not slash or not re.fullmatch(r"[A-Za-z][A-Za-z0-9.+-]*", kind):
        raise InputError("invalid PURL type or package path")
    kind = kind.lower()
    parts = path.split("/")
    name_version = parts.pop()
    name, marker, version = name_version.partition("@")
    if marker and (not version or "@" in version):
        raise InputError("invalid PURL version")
    decoded_parts = [_decode(part) for part in parts]
    name = _decode(name)
    if any("/" in part or part in {".", ".."} for part in [*decoded_parts, name]):
        raise InputError("unsupported PURL path segment")
    namespace, name = _normalize(kind, "/".join(decoded_parts), name)
    _shape(kind, namespace, name)
    qualifiers = {}
    if query_marker:
        if not query:
            raise InputError("empty PURL qualifiers")
        for pair in query.split("&"):
            key, equals, val = pair.partition("=")
            key = key.lower()
            if not equals or not re.fullmatch(r"[a-z][a-z0-9._-]*", key) or key in qualifiers:
                raise InputError("invalid or duplicate PURL qualifier")
            qualifiers[key] = _decode(val)
    subpath = []
    if "#" in value:
        subpath = [_decode(part) for part in fragment.split("/")]
        if any(part in {".", ".."} or "/" in part for part in subpath):
            raise InputError("unsupported PURL subpath")
    return {
        "type": kind, "namespace": namespace, "name": name,
        "version": _decode(version) if marker else None,
        "qualifiers": dict(sorted(qualifiers.items())), "subpath": "/".join(subpath),
    }


def format_purl(parts, *, with_version=True):
    path = "/".join(_encode(p) for p in parts["namespace"].split("/") if p)
    result = "pkg:" + parts["type"] + "/" + (path + "/" if path else "") + _encode(parts["name"])
    if with_version and parts["version"] is not None:
        result += "@" + _encode(parts["version"])
    if parts["qualifiers"]:
        result += "?" + "&".join(k + "=" + _encode(v) for k, v in sorted(parts["qualifiers"].items()))
    if parts["subpath"]:
        result += "#" + "/".join(_encode(p) for p in parts["subpath"].split("/"))
    return result


def package_identity(name, version, eco=None, purl=None):
    """Unknown identity has no merge key; the merger isolates each observation."""
    if name is not None:
        name = token(name)
    if version is not None:
        version = token(version)
    kind = ecosystem(eco)
    if purl is not None:
        parts = parse_purl(purl)
        _check_reported_name(name, parts)
        if kind and kind != parts["type"]:
            raise InputError("package ecosystem contradicts PURL type")
        if version is not None and parts["version"] is not None and version != parts["version"]:
            raise InputError("installed version contradicts PURL version")
        version = version or parts["version"]
        if version is None:
            raise InputError("installed package version is required")
        parts["version"] = version
        known = parts["type"] in PURL_TYPES
        reason = None if known else "unsupported-purl-type"
        if parts["type"] in {"deb", "rpm", "apk"} and not parts["namespace"] and not parts["qualifiers"].get("distro"):
            known, reason = False, "missing-os-distribution"
        return {
            **parts, "known": known, "identity": format_purl(parts) if known else None,
            "purl": format_purl(parts), "reportedName": name, "reportedEcosystem": eco,
            "reason": reason,
        }
    if name is None or version is None:
        raise InputError("package name and installed version are required without a PURL")
    namespace = ""
    if kind == "npm" and name.startswith("@") and name.count("/") == 1:
        namespace, name = name.split("/")
    elif kind == "maven" and name.count(":") == 1:
        namespace, name = name.split(":")
    elif kind == "golang" and "/" in name:
        namespace, name = name.rsplit("/", 1)
    elif "/" in name or "@" in name or ":" in name:
        # Valid opaque names can occur in unsupported ecosystems; don't invent a PURL.
        if kind in FALLBACK_TYPES:
            raise InputError("unsupported package name for the reported ecosystem")
    if not name or (kind == "maven" and not namespace) or (kind == "npm" and namespace == "@"):
        raise InputError("malformed package name or missing namespace")
    _shape(kind, namespace, name)
    namespace, canonical_name = _normalize(kind, namespace, name)
    known = kind in FALLBACK_TYPES
    parts = {"type": kind, "namespace": namespace, "name": canonical_name, "version": version,
             "qualifiers": {}, "subpath": ""}
    return {**parts, "known": known, "identity": format_purl(parts) if known else None,
            "purl": None, "reportedName": (namespace + "/" + name if kind == "npm" and namespace else
                                           namespace + ":" + name if kind == "maven" and namespace else
                                           namespace + "/" + name if kind == "golang" and namespace else name),
            "reportedEcosystem": eco,
            "reason": None if known else "missing-or-unsupported-ecosystem-or-os-purl"}
