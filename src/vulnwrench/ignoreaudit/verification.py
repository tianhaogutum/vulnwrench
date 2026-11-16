"""Read-only identity verification for retained JSON cleanup-plan inputs."""
import re

from .cleanup import SUGGESTIONS
from .inputs import advisory, apply_metadata, array, digest, json_data, load_aliases, load_report, load_rules, obj
from .model import InputError


LOCATORS = {
    'trivy': (re.compile(r'line:[1-9][0-9]*\Z'), 'utf8_splitlines_1_based'),
    'osv': (re.compile(r'IgnoredVulns:(?:0|[1-9][0-9]*)\Z'), 'toml_IgnoredVulns_index_0_based'),
}


def _plan_identity(raw_plan):
    """Check the schema and identity envelope, without re-auditing its context."""
    plan = obj(json_data(raw_plan), where='cleanup plan')
    if type(plan.get('schemaVersion')) is not int or plan['schemaVersion'] != 1:
        raise InputError('cleanup plan: unsupported schemaVersion')
    if plan.get('tool') != 'ignore-audit' or plan.get('command') != 'cleanup-plan':
        raise InputError('cleanup plan: expected a vulnwrench ignores JSON cleanup-plan (tool "ignore-audit")')
    if (plan.get('reviewOnly') is not True or plan.get('automaticChangesAllowed') is not False or
            plan.get('unusedRuleAssertionAllowed') is not False):
        raise InputError('cleanup plan: incompatible review-only safeguards')
    provenance = obj(plan.get('provenance'), where='cleanup plan provenance')
    native_format = provenance.get('format')
    if not isinstance(native_format, str) or native_format not in LOCATORS:
        raise InputError('cleanup plan: unsupported native format')
    return plan, provenance, native_format


def _check_plan_pin(raw_plan, expected_plan_sha256, where):
    """Optionally pin complete raw bytes before parsing; equality grants no trust."""
    if expected_plan_sha256 is None:
        return None
    if not isinstance(expected_plan_sha256, str) or not re.fullmatch(r'[0-9a-f]{64}', expected_plan_sha256):
        raise InputError(f'{where}: expected plan SHA-256 must be 64 lowercase hexadecimal characters')
    plan_digest = digest(raw_plan)
    if plan_digest != expected_plan_sha256:
        raise InputError(f'{where}: expected plan SHA-256 mismatch')
    return plan_digest


def verify_cleanup_plan_identity(raw_plan, *, expected_plan_sha256):
    """Pin complete retained plan bytes and check only the supported envelope.

    No bound input is read or verified. Context, references, counts, decisions,
    matching and coverage are uninterpreted; equality is not authentication,
    semantic plan approval or permission to remove or edit anything.
    """
    if expected_plan_sha256 is None:
        raise InputError('cleanup plan identity: expected plan SHA-256 is required')
    plan_digest = _check_plan_pin(raw_plan, expected_plan_sha256, 'cleanup plan identity')
    _plan_identity(raw_plan)
    return {'command': 'verify-cleanup-plan-identity', 'planIdentityVerified': True,
            'planSha256': plan_digest, 'automaticChangesAllowed': False}


def verify_cleanup_source(raw_plan, raw_rules, *, expected_plan_sha256=None):
    """Verify every reference, counting unique native locators only afterward.

    This does not authenticate the plan, re-audit a report or authorize edits.
    Exclusions record only a key; candidates also carry an advisory to compare.
    The strict native parser validates the IDs resolved by both kinds of entry.
    An optional external digest pins raw plan identity without adding trust or
    requiring reports, sidecars or maps, even when bound in plan provenance.
    """
    plan_digest = _check_plan_pin(raw_plan, expected_plan_sha256, 'cleanup source')
    plan, provenance, rule_format = _plan_identity(raw_plan)
    rules_digest = digest(raw_rules)
    if provenance.get('rulesSha256') != rules_digest:
        raise InputError('cleanup source: provenance rulesSha256 mismatch')
    # Parse complete retained bytes even with zero references. Scope, reports,
    # sidecars and aliases are unnecessary for native locator/ID resolution.
    rules = {rule.key: rule for rule in load_rules(raw_rules, rule_format)}
    locator_pattern, convention = LOCATORS[rule_format]
    groups = obj(plan.get('groups'), where='cleanup plan groups')
    if set(groups) != {group for group, *_ in SUGGESTIONS}:
        raise InputError('cleanup plan: unsupported review groups')
    verified = set()

    def check(entry, excluded=False):
        obj(entry, where='cleanup plan entry')
        if entry.get('definiteRemovalRecommended') is not False:
            raise InputError('cleanup plan: incompatible manual-review safeguard')
        row = entry if excluded else obj(entry.get('rule'), where='cleanup plan rule')
        key = row.get('key')
        if not isinstance(key, str) or not locator_pattern.fullmatch(key) or key not in rules:
            raise InputError('cleanup source: invalid or unresolved native locator')
        ref = obj(entry.get('sourceReference'), where='cleanup source reference')
        expected = {'rulesSha256': rules_digest, 'rulesByteLength': len(raw_rules), 'format': rule_format,
                    'locatorConvention': convention, 'locator': key}
        # Dict equality alone would accept boolean/float lengths equal to ints.
        if type(ref.get('rulesByteLength')) is not int or ref != expected:
            raise InputError('cleanup source: inconsistent source reference')
        if not excluded and advisory(row.get('rule'), 'cleanup plan advisory') != rules[key].advisory:
            raise InputError('cleanup source: advisory mismatch')
        verified.add(key)

    for entries in groups.values():
        for entry in array(entries, 'cleanup plan candidates'):
            check(entry)
    for entry in array(plan.get('excludedFromOrphanReview'), 'cleanup plan exclusions'):
        check(entry, excluded=True)
    result = {'command': 'verify-cleanup-source', 'sourceVerified': True, 'rulesSha256': rules_digest,
              'verifiedReferenceCount': len(verified), 'automaticChangesAllowed': False}
    if plan_digest is not None:
        result['planSha256'] = plan_digest
    return result


def verify_cleanup_report(raw_plan, raw_report, *, expected_plan_sha256=None):
    """Verify complete retained report identity, never coverage or removability.

    Parsing uses the native adapter's acknowledgment precondition only; its
    coverage/findings are discarded and no unfilteredness claim is returned.
    No rules, sidecars or aliases are needed for report identity verification.
    An optional external digest pins complete raw plan identity before parsing;
    it neither authenticates decisions nor bypasses report validation.
    """
    plan_digest = _check_plan_pin(raw_plan, expected_plan_sha256, 'cleanup report')
    _, provenance, native_format = _plan_identity(raw_plan)
    report_digest = digest(raw_report)
    if provenance.get('reportSha256') != report_digest:
        raise InputError('cleanup report: provenance reportSha256 mismatch')
    # A matching self-declared hash cannot make an unsupported report valid.
    # Parse even when the plan has zero candidates/exclusions. Absent/null
    # observation collections remain acceptable under existing native semantics.
    load_report(raw_report, native_format, report_unfiltered=True)
    result = {'command': 'verify-cleanup-report', 'reportVerified': True,
              'reportSha256': report_digest, 'automaticChangesAllowed': False}
    if plan_digest is not None:
        result['planSha256'] = plan_digest
    return result


def verify_cleanup_alias_map(raw_plan, raw_aliases, *, expected_plan_sha256=None):
    """Verify retained explicit-local-map identity, never equivalence or trust.

    No report hints, audit decisions or source references are re-evaluated.
    A self-declared digest does not authenticate a mutually edited pair.
    An optional external digest pins complete raw plan identity before parsing;
    it neither authenticates equivalence nor bypasses map validation.
    """
    plan_digest = _check_plan_pin(raw_plan, expected_plan_sha256, 'cleanup alias map')
    _, provenance, _ = _plan_identity(raw_plan)
    if provenance.get('aliases') != 'explicit_local_groups':
        raise InputError('cleanup alias map: explicit_local_groups provenance required')
    alias_digest = digest(raw_aliases)
    if provenance.get('aliasMapSha256') != alias_digest:
        raise InputError('cleanup alias map: provenance aliasMapSha256 mismatch')
    # Parse the complete strict schema-1 disjoint groups even with no plan
    # references or map members. A matching hash cannot legitimize bad groups.
    load_aliases(raw_aliases)
    result = {'command': 'verify-cleanup-alias-map', 'aliasMapVerified': True,
              'aliasMapSha256': alias_digest, 'automaticChangesAllowed': False}
    if plan_digest is not None:
        result['planSha256'] = plan_digest
    return result


def verify_cleanup_metadata(raw_plan, raw_rules, raw_metadata, *, expected_plan_sha256=None):
    """Verify retained rules/sidecar identity, never annotations or decisions.

    The existing metadata validator checks native locators, the sidecar's rule
    hash and reason conflicts. Its annotated rules are discarded; no matching,
    report coverage or plan source references are re-evaluated. An optional
    external digest pins complete raw plan identity before parsing; it neither
    authenticates annotations/decisions nor bypasses native/sidecar validation.
    """
    plan_digest = _check_plan_pin(raw_plan, expected_plan_sha256, 'cleanup metadata')
    _, provenance, native_format = _plan_identity(raw_plan)
    rules_digest, metadata_digest = digest(raw_rules), digest(raw_metadata)
    if provenance.get('rulesSha256') != rules_digest:
        raise InputError('cleanup metadata: provenance rulesSha256 mismatch')
    if provenance.get('metadataSha256') != metadata_digest:
        raise InputError('cleanup metadata: provenance metadataSha256 mismatch')
    # Parse both complete inputs even for empty rules/annotations and plans
    # with zero references. Matching self-declared hashes do not authenticate
    # owners/reasons or legitimize unsupported native rules or sidecars.
    rules = load_rules(raw_rules, native_format)
    apply_metadata(rules, raw_metadata, rules_digest)
    result = {'command': 'verify-cleanup-metadata', 'metadataVerified': True,
            'metadataSha256': metadata_digest, 'rulesSha256': rules_digest,
            'automaticChangesAllowed': False}
    if plan_digest is not None:
        result['planSha256'] = plan_digest
    return result


def verify_cleanup_inputs(raw_plan, raw_rules, raw_report, raw_metadata=None, raw_aliases=None,
                          *, expected_plan_sha256=None):
    """Compose existing checks against one retained plan byte snapshot.

    Optional inputs must exactly match provenance; no bound input can be
    silently skipped. Identity and native source references do not authenticate
    plan decisions, annotations, alias equivalence or report completeness.
    An optional external digest pins the complete plan bytes before parsing;
    equality cannot bypass any existing check and is not authentication.
    """
    plan_digest = _check_plan_pin(raw_plan, expected_plan_sha256, 'cleanup inputs')
    _, provenance, _ = _plan_identity(raw_plan)
    if ('metadataSha256' in provenance) != (raw_metadata is not None):
        raise InputError('cleanup inputs: metadata input must match provenance')
    alias_mode = provenance.get('aliases')
    if alias_mode == 'exact_ids_only':
        if 'aliasMapSha256' in provenance or raw_aliases is not None:
            raise InputError('cleanup inputs: exact IDs cannot bind an alias map')
    elif alias_mode == 'explicit_local_groups':
        if 'aliasMapSha256' not in provenance or raw_aliases is None:
            raise InputError('cleanup inputs: explicit local groups require a retained alias map')
    else:
        raise InputError('cleanup inputs: unsupported alias provenance')

    source = verify_cleanup_source(raw_plan, raw_rules)
    report = verify_cleanup_report(raw_plan, raw_report)
    result = {'command': 'verify-cleanup-inputs', 'inputsVerified': True,
              'rulesSha256': source['rulesSha256'], 'reportSha256': report['reportSha256'],
              'verifiedReferenceCount': source['verifiedReferenceCount'], 'automaticChangesAllowed': False}
    if raw_metadata is not None:
        result['metadataSha256'] = verify_cleanup_metadata(raw_plan, raw_rules, raw_metadata)['metadataSha256']
    if raw_aliases is not None:
        result['aliasMapSha256'] = verify_cleanup_alias_map(raw_plan, raw_aliases)['aliasMapSha256']
    if plan_digest is not None:
        result['planSha256'] = plan_digest
    return result
