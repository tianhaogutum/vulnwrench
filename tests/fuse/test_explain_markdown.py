"""Selected explanation Markdown: evidence preservation, inert text and CLI guards."""
from copy import deepcopy
import hashlib
import html
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

import vulnwrench.fuse as vf
from .test_explain import API, ADVISORY, WORKER, ROOT, args, cli, reports

SELECT = ['--advisory', ADVISORY, '--package', API]


def appendix(markdown):
    prefix, block = markdown.split('## Complete explanation JSON\n\n', 1)
    lines = block.splitlines()
    fence = lines[0].removesuffix('json')
    assert re.fullmatch(r'`{3,}', fence)
    assert lines[-1] == fence
    payload = '\n'.join(lines[1:-1])
    assert len(fence) > max((len(m[0]) for m in re.finditer(r'`+', payload)), default=0)
    return prefix, json.loads(payload)


def explanation(items=None, **selectors):
    return vf.explain_finding(vf.merge_reports(items or reports()), **(selectors or {'advisory':ADVISORY, 'package':API}))


class ExplainMarkdownTests(unittest.TestCase):
    def test_cli_selected_fixture_preserves_direct_links_conflicts_and_external_witness(self):
        result = cli('explain', *args(), *SELECT, '--format', 'markdown')
        self.assertEqual(result.returncode, 0, result.stderr)
        body, obj = appendix(result.stdout)
        self.assertEqual(obj, explanation())
        visible = html.unescape(body)
        self.assertIn(API, visible)
        self.assertIn(WORKER, visible)
        for key in ('severityConflict', 'fixConflict', 'fixVersionConflict', 'fixStateConflict'):
            self.assertIn(f'| {key} | {json.dumps(obj["finding"][key])} |', visible)
        self.assertIn('| remediationAssessment | not-evaluated |', visible)
        self.assertEqual(sum(e['contributesToFinding'] for e in obj['evidence']), 2)
        self.assertEqual(len(obj['evidence']), 3)
        contributing = body.split('## Contributing observations\n',1)[1].split('## Noncontributing alias witnesses\n',1)[0]
        external = body.split('## Noncontributing alias witnesses\n',1)[1].split('## Input provenance\n',1)[0]
        self.assertEqual(contributing.count('| contributesToFinding | true |'), 2)
        self.assertEqual(external.count('| contributesToFinding | false |'), 1)
        links = html.unescape(body.split('## Direct alias assertions\n',1)[1].split('## Contributing observations\n',1)[0])
        rows = [row for row in links.splitlines() if row.startswith('| ')][2:]
        self.assertEqual(len(rows), 2)
        for edge in obj['aliasLinks']:
            self.assertTrue(any(all(str(value) in row for value in edge.values()) for row in rows))
        self.assertFalse(any('OSV-EXPLAIN-1' in row and 'CVE-EXPLAIN-1' in row for row in rows))
        self.assertIn('manifest-not-supplied', visible)
        self.assertIn('canEstablishFixed', visible)
        self.assertEqual(result.stdout, vf.render_explanation_markdown(obj))

    def test_json_default_explicit_and_live_saved_markdown_bytes_match(self):
        live_json = cli('explain', *args(), *SELECT)
        self.assertEqual(live_json.returncode, 0, live_json.stderr)
        self.assertEqual(live_json.stdout, cli('explain', *args(), *SELECT, '--format','json').stdout)
        self.assertEqual(live_json.stdout, (ROOT/'examples/fuse/expected/explanation.json').read_text())
        live = cli('explain', *args(), *SELECT, '--format','markdown')
        saved = cli('explain', '--merged','examples/fuse/explain/merged.json', *SELECT, '--format','markdown')
        self.assertEqual(saved.returncode, 0, saved.stderr)
        self.assertEqual(saved.stdout, live.stdout)
        selected = appendix(saved.stdout)[1]
        by_id = cli('explain', '--merged','examples/fuse/explain/merged.json', '--finding',selected['finding']['findingId'], '--format','markdown')
        self.assertEqual(by_id.returncode, 0, by_id.stderr)
        self.assertEqual(by_id.stdout, saved.stdout)
        self.assertEqual(saved.stdout, vf.render_explanation_markdown(explanation(reports()[::-1])))

    def test_pure_renderer_escapes_hostile_values_and_complete_appendix_roundtrips(self):
        hostile = '|\n# heading\r\n```\n````````\n<img src=x> [click](file:///secret) &amp; \\ _* ~\t\u2028'
        doc = {'matches':[{'artifact':{'name':'demo','version':'1','type':'npm','locations':[{'path':'path|`<x> [click](file:///secret) &amp;'}]},
            'vulnerability':{'id':'A|`<x>','severity':'High'},
            'relatedVulnerabilities':[{'id':'B|`<x>'}], hostile: {'extension': hostile}}]}
        source = vf.Report.from_document('grype', doc, 'source|`<x>')
        manifest = vf.CoverageManifest.from_document({'schemaVersion':'vulnfuse-coverage-1', 'inputs':[
            {'scanner':'grype','input':source.input_name,'sha256':source.sha256,'scanComplete':True,
             'targetIdentity':'target|`<x>','scanPolicyIdentity':'policy|`<x>','databaseIdentity':'db|`<x>',
             'databaseTimestamp':'2026-11-10T00:00:00Z'}]}, 'manifest|`<x>')
        obj = vf.explain_finding(vf.merge_reports([source], coverage_manifest=manifest), advisory='A|`<x>')
        before = deepcopy(obj)
        with patch('builtins.open', side_effect=AssertionError('renderer opened a path')), patch('vulnwrench.fuse.core.merge_reports', side_effect=AssertionError('renderer merged')):
            rendered = vf.render_explanation_markdown(obj)
            self.assertEqual(rendered, vf.render_explanation_markdown(obj))
        self.assertEqual(obj, before)
        body, restored = appendix(rendered)
        self.assertEqual(restored, obj)
        self.assertNotIn('<img', body)
        self.assertNotIn('```', body)
        self.assertNotIn('\r', body)
        self.assertNotIn('\t', body)
        self.assertNotIn('\u2028', body)
        self.assertNotIn('[click]', body)
        for line in body.splitlines():
            if line.startswith('| '):
                self.assertIn(line.count('|'), (3, 8))
        self.assertIn('&#96;', body)
        self.assertIn('&#60;', body)
        self.assertIn('&#124;', body)
        for field in obj['evidence'][0]['packageEvidence'] + obj['evidence'][0]['pathEvidence']:
            self.assertIn(field['pointer'], html.unescape(body))
        self.assertIn(source.sha256, body)
        self.assertIn(manifest.sha256, body)
        # File names retained by read_report can contain line breaks even though
        # declared coverage labels and Report.from_document names reject them.
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / ('source' + hostile + 'end').replace('/', '-')
            path.write_text(vf.dumps(doc))
            multiline = explanation([vf.read_report('grype', path)], advisory='A|`<x>')
            escaped, restored = appendix(vf.render_explanation_markdown(multiline))
            self.assertEqual(restored, multiline)
            self.assertIn('&#10;', escaped)
            self.assertIn('&#13;', escaped)
            self.assertNotIn('\n# heading', escaped)

    def test_unknown_identities_empty_conflicts_and_repeated_alias_assertions(self):
        unknown = vf.Report.from_document('trivy', {'Results':[{'Type':'unknown','Vulnerabilities':[
            {'VulnerabilityID':'A','PkgName':'demo','InstalledVersion':'1'}]}]})
        merged = vf.merge_reports([unknown, unknown])
        self.assertEqual(merged['findingCount'], 2)
        for finding in merged['findings']:
            obj = vf.explain_finding(merged, finding_id=finding['findingId'])
            body, restored = appendix(vf.render_explanation_markdown(obj))
            self.assertEqual(restored, obj)
            self.assertFalse(obj['finding']['package']['known'])
            self.assertIn('| severityConflict | false |', body)
            self.assertIn('| fixConflict | false |', body)
            self.assertIn('None reported.', body)
        repeated = vf.Report.from_document('grype', {'matches':[{'artifact':{'name':'demo','version':'1','type':'npm'},
            'vulnerability':{'id':'A'}, 'relatedVulnerabilities':[{'id':'B'},{'id':'B'}]}]})
        obj = explanation([repeated,repeated], advisory='B')
        body, restored = appendix(vf.render_explanation_markdown(obj))
        self.assertEqual(restored, obj)
        self.assertEqual(len(obj['aliasLinks']),4)
        self.assertEqual(body.count('| contributesToFinding | true |'), 2)
        self.assertEqual(obj['finding']['observationCount'],2)
        self.assertIn('| absenceAssessments |', body)

    def test_matching_pins_and_invalid_data_selectors_and_modes_preserve_output(self):
        with tempfile.TemporaryDirectory() as td:
            saved, output = Path(td)/'saved.json', Path(td)/'out.md'
            saved.write_bytes((ROOT/'examples/fuse/explain/merged.json').read_bytes())
            digest = hashlib.sha256(saved.read_bytes()).hexdigest()
            good = cli('explain','--merged',saved,'--merged-sha256',digest,*SELECT,'--format','markdown','--output',output)
            self.assertEqual(good.returncode,0,good.stderr)
            self.assertEqual(good.stdout,'')
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            expected = output.read_bytes()
            cases = [
                ['explain','--merged',saved,'--merged-sha256','0'*64,*SELECT],
                ['explain','--merged',saved,'--merged-sha256','bad',*SELECT],
                ['explain','--merged',saved,'--advisory',ADVISORY],
                ['explain','--merged',saved,'--finding','missing'],
                ['explain','--merged',saved,'--finding','f0001','--package',API],
                ['explain','--merged',saved,*SELECT,'--trivy','examples/fuse/explain/trivy.json'],
                ['explain','--merged','examples/fuse/explain/dangling-alias.json',*SELECT],
                ['explain',*args(),'--osv','examples/fuse/unsupported.json',*SELECT],
                ['explain',*args(),*SELECT,'--format','html'],
                ['merge',*args()], ['validate','--merged',saved],
                ['validate-input','--scanner','trivy','--input','examples/fuse/trivy.json'],
                ['validate-coverage','--trivy','examples/fuse/trivy.json','--coverage-manifest','examples/fuse/coverage.json']]
            for command in cases:
                with self.subTest(command=command):
                    failed = cli(*command,'--format','markdown','--output',output)
                    self.assertEqual(failed.returncode,2,failed.stderr)
                    self.assertEqual(failed.stdout,'')
                    self.assertEqual(output.read_bytes(),expected)
                    self.assertNotIn('Traceback',failed.stderr)
            obj = json.loads(saved.read_text()); obj['findings'][-1]['observations'].clear()
            saved.write_text(vf.dumps(obj))
            failed = cli('explain','--merged',saved,'--merged-sha256',hashlib.sha256(saved.read_bytes()).hexdigest(),*SELECT,'--format','markdown','--output',output)
            self.assertEqual(failed.returncode,2)
            self.assertEqual(output.read_bytes(),expected)
            output.unlink()
            self.assertEqual(cli('explain','--merged',saved,*SELECT,'--format','markdown','--output',output).returncode,2)
            self.assertFalse(output.exists())

    def test_live_manifest_input_pins_assessments_and_alias_guards(self):
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td)
            source, absent, manifest, saved, output = (folder/n for n in ['source','absent','manifest','saved','out.md'])
            source.write_text('{"Results":[{"Type":"npm","Vulnerabilities":[{"VulnerabilityID":"A","PkgName":"demo","InstalledVersion":"1"}]}]}')
            absent.write_text('{"matches":[]}')
            reports_ = [vf.read_report('trivy',source), vf.read_report('grype',absent)]
            declarations = [{'scanner':r.scanner,'input':r.input_name,'sha256':r.sha256,'scanComplete':True,
                'targetIdentity':'target','databaseTimestamp':'2026-11-10T00:00:00Z',
                'databaseIdentity':'db','scanPolicyIdentity':str(i)} for i,r in enumerate(reports_)]
            manifest.write_text(vf.dumps({'schemaVersion':'vulnfuse-coverage-1','inputs':declarations}))
            base = ['explain','--trivy',source,'--grype',absent,'--coverage-manifest',manifest,'--advisory','A','--format','markdown']
            pins = ['--coverage-manifest-sha256',hashlib.sha256(manifest.read_bytes()).hexdigest()]
            for r in reports_:
                pins += ['--expect-input-sha256',r.scanner,r.input_name,r.sha256]
            good = cli(*base,*pins)
            self.assertEqual(good.returncode,0,good.stderr)
            body,obj = appendix(good.stdout)
            self.assertIn('scan-policy-mismatch',html.unescape(body))
            self.assertIn('canEstablishFixed',body)
            self.assertIn('comparedTo',body)
            saved.write_text(vf.dumps(vf.merge_reports(reports_,coverage_manifest=vf.read_coverage_manifest(manifest))))
            loaded = cli('explain','--merged',saved,'--advisory','A','--format','markdown')
            self.assertEqual(loaded.returncode,0,loaded.stderr)
            self.assertEqual(loaded.stdout,good.stdout)
            for bad in [['--coverage-manifest-sha256','0'*64], ['--expect-input-sha256','trivy',source,'0'*64]]:
                output.write_text('sentinel')
                failed = cli(*base,*bad,'--output',output)
                self.assertEqual(failed.returncode,2)
                self.assertEqual(failed.stdout,'')
                self.assertEqual(output.read_text(),'sentinel')
            for protected in (source,absent,manifest,saved):
                original = protected.read_bytes()
                hard, sym = folder/'hard', folder/'sym'
                hard.hardlink_to(protected); sym.symlink_to(protected)
                for destination in (protected,hard,sym):
                    command = base if protected != saved else ['explain','--merged',saved,'--advisory','A','--format','markdown']
                    result = cli(*command,'--output',destination)
                    self.assertEqual(result.returncode,2)
                    self.assertEqual(result.stdout,'')
                    self.assertEqual(protected.read_bytes(),original)
                hard.unlink(); sym.unlink()
            source.unlink(); absent.unlink(); manifest.unlink()
            without_originals = cli('explain','--merged',saved,'--advisory','A','--format','markdown')
            self.assertEqual(without_originals.returncode,0,without_originals.stderr)
            self.assertEqual(without_originals.stdout,good.stdout)


if __name__ == '__main__':
    unittest.main()
