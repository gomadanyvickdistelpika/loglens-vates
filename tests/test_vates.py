"""Vates support: XCP-ng host / pool and Xen Orchestra (XO) detection, rules, ranking, KB honesty and synthetic scenarios."""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, '..')
sys.path.insert(0, ROOT)
from lvx import kb, templates                                  # noqa: E402
from lvx.analyzer import Analyzer, classify_product, is_log_candidate   # noqa: E402
from lvx.bundle import open_bundle                             # noqa: E402
from lvx.rules import R, BY_ID                                 # noqa: E402

VATES_RULES = [r for r in R if r['product'] in ('xcpng', 'xo')]
ALLOWED_HOSTS = {'xcp-ng.org', 'docs.xcp-ng.org', 'xen-orchestra.com', 'docs.xen-orchestra.com', 'github.com', 'forum.vates.tech', 'forums.xcp-ng.org'}
SYN = 'SYNTHETIC SCENARIO built from public Vates forum/docs search summaries, not a resolved support case'


def analyse(tid):
    d = tempfile.mkdtemp(prefix='lvx_vt_')
    try:
        m = templates.build_bundle(tid, d)
        b = open_bundle('t', d)
        try:
            return Analyzer(b, issue=m['issue'], anchor=m['anchor']).run()
        finally:
            b.close()
    finally:
        shutil.rmtree(d, ignore_errors=True)


class Detection(unittest.TestCase):
    def test_xcpng_files_classified(self):
        for p in ('var/log/xensource.log', 'var/log/SMlog', 'var/log/SMlog.1.gz', 'var/log/xha.log', 'var/log/xen/hypervisor.log', 'var/log/xenopsd.log'):
            self.assertEqual(classify_product(p), 'xcpng', p)
            self.assertTrue(is_log_candidate(p), p)
        for p in ('var/log/daemon.log', 'var/log/kern.log', 'var/log/messages'):
            self.assertTrue(is_log_candidate(p), p)

    def test_xo_files_classified(self):
        for p in ('xo/journalctl-xo-server.txt', 'xo/xo-server.log', 'var/log/xo-server/xo-server.log', 'xo/journalctl-xoa-updater.txt'):
            self.assertEqual(classify_product(p), 'xo', p)
            self.assertTrue(is_log_candidate(p), p)

    def test_vmware_classification_unchanged(self):
        self.assertEqual(classify_product('var/run/log/vmkernel.log'), 'esxi')
        self.assertEqual(classify_product('var/run/log/hostd.log'), 'esxi')
        self.assertEqual(classify_product('var/log/vmware/vpxd/vpxd-1.log'), 'vcenter')
        self.assertEqual(classify_product('var/log/vmware/sts/sts-runtime.log'), 'vcenter')
        self.assertEqual(classify_product('var/log/messages'), 'unknown')

    def test_bundle_products(self):
        self.assertEqual(analyse('CT-50')['products'], ['xcpng'])
        self.assertEqual(analyse('CT-60')['products'], ['xo'])
        self.assertEqual(analyse('CT-54')['products'], ['xcpng', 'xo'])

    def test_vmware_rules_do_not_fire_on_vates_only_bundle(self):
        ids = {f['id'] for f in analyse('CT-53')['findings']}
        self.assertFalse({i for i in ids if i.startswith(('esx.psod', 'esx.snapshot', 'vc.'))}, ids)

    def test_xcp_rules_do_not_fire_on_vmware_bundle(self):
        d = tempfile.mkdtemp(prefix='lvx_vt_')
        try:
            m = templates.build_bundle('CT-13', d)
            b = open_bundle('t', d)
            try:
                res = Analyzer(b, issue=m['issue'], anchor=m['anchor']).run()
            finally:
                b.close()
            self.assertFalse([f['id'] for f in res['findings'] if f['id'].startswith('xcp.')])
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_syslog_only_bundle_gets_incident_year(self):
        res = analyse('CT-50')
        self.assertGreater(res['stats']['lines_in_window'], 0)
        self.assertTrue(res['findings'])


class RuleHygiene(unittest.TestCase):
    def test_prefilter_never_hides_a_regex_hit(self):
        """For every planted template line: if a rule's regex matches, its keyword prefilter must also match (else the rule is dead)."""
        self.assertGreaterEqual(len(VATES_RULES), 14)
        for r in VATES_RULES:
            self.assertTrue(r['kws'], r['id'])
        for t in templates.all_templates():
            for _off, _f, text, _b in t['lines']:
                for r in R:
                    if r['rx'].search(text):
                        low = text.lower()
                        self.assertTrue(any(k in low for k in r['kws']), '%s: %s matches %s but not its kw prefilter' % (t['id'], r['id'], text[:80]))

    def test_each_vates_rule_fires_on_its_scenario(self):
        for t in templates.all_templates():
            if t['id'] < 'CT-50':
                continue
            for exp in t['expect_rules']:
                hit = [ln for ln in t['lines'] if BY_ID[exp]['rx'].search(ln[2]) and any(k in ln[2].lower() for k in BY_ID[exp]['kws'])]
                self.assertTrue(hit, '%s: no planted line triggers %s' % (t['id'], exp))
        covered = {e for t in templates.all_templates() for e in t['expect_rules']}
        self.assertEqual([r['id'] for r in VATES_RULES if r['id'] not in covered], [])

    def test_severity_advice_and_search_present(self):
        for r in VATES_RULES:
            self.assertIn(r['severity'], ('critical', 'high', 'medium', 'low'))
            self.assertGreater(len(r['advice']), 60, r['id'])
            self.assertTrue(r['search'] and r['topics'], r['id'])

    def test_ranking_links_resolve(self):
        for r in VATES_RULES:
            for x in r['root_for']:
                self.assertIn(x, BY_ID)


class Ranking(unittest.TestCase):
    def test_sr_full_over_coalesce_over_vm_start(self):
        sc = {f['id']: f['score'] for f in analyse('CT-53')['findings']}
        self.assertGreater(sc['xcp.sr_full'], sc['xcp.coalesce_stuck'])
        self.assertGreater(sc['xcp.coalesce_stuck'], sc['xcp.sr_chain'])
        self.assertGreater(sc['xcp.sr_full'], sc['xcp.vm_start_fail'])
        self.assertGreater(sc['xcp.coalesce_stuck'], sc['xcp.vm_start_fail'])

    def test_disk_full_over_xapi_down(self):
        res = analyse('CT-50')
        order = [f['id'] for f in res['findings']]
        self.assertLess(order.index('xcp.host_disk_full'), order.index('xcp.xapi_down'))
        self.assertTrue(next(f for f in res['findings'] if f['id'] == 'xcp.xapi_down').get('symptom_of'))

    def test_ha_fence_over_master_unreachable(self):
        order = [f['id'] for f in analyse('CT-52')['findings']]
        self.assertLess(order.index('xcp.ha_fence'), order.index('xcp.master_unreachable'))


class KbHonesty(unittest.TestCase):
    def test_vates_articles_are_urls_on_public_vates_hosts_with_seen_date(self):
        n = 0
        for e in kb._load()['entries']:
            for a in e['articles']:
                if str(a['id']).startswith('https://'):
                    n += 1
                    self.assertIn(urlparse(a['id']).hostname, ALLOWED_HOSTS, a['id'])
                    self.assertRegex(a.get('seen', ''), r'^\d{4}-\d\d-\d\d$', a['id'])
                    self.assertTrue(a['title'])
        self.assertGreater(n, 40)
        for t in templates.all_templates():
            for k in t['kb']:
                if k['id'].startswith('https://'):
                    self.assertIn(urlparse(k['id']).hostname, ALLOWED_HOSTS, k['id'])
                    self.assertTrue(k.get('seen'), k['id'])

    def test_every_vates_template_kb_url_is_in_the_library(self):
        lib = {a['id'] for e in kb._load()['entries'] for a in e['articles']}
        for t in templates.all_templates():
            if t['id'] >= 'CT-50':
                for k in t['kb']:
                    self.assertIn(k['id'], lib, '%s cites %s which is not in the researched library' % (t['id'], k['id']))

    def test_summary_only_is_stated(self):
        lib = kb._load()
        self.assertIn('not read', lib['vates_source'])
        for f in analyse('CT-53')['findings']:
            if f['id'].startswith('xcp.'):
                r = f['kb_research']
                self.assertEqual(r['vendor'], 'Vates/XCP-ng')
                if r['status'] == 'found':
                    self.assertIn('article text was not read', r['message'])
                    for en in r['entries']:
                        for a in en['articles']:
                            self.assertTrue(a['url'].startswith('https://'))
                            self.assertTrue(a['seen'])

    def test_none_wording_for_vates(self):
        r = kb.research('xcp.vm_start_fail', 'nothing that matches', 'x')
        self.assertIn(r['status'], ('found', 'none'))
        if r['status'] == 'none':
            self.assertIn('No Vates/XCP-ng article found', r['message'])

    def test_broadcom_wording_unchanged(self):
        r = kb.research('esx.psod', 'nothing specific', 'x')
        self.assertEqual(r['vendor'], 'Broadcom')
        self.assertIn('No Broadcom KB found', r['message'])


class Scenarios(unittest.TestCase):
    CATEGORIES = {'xo': 'CT-59', 'host': 'CT-50', 'vm': 'CT-56', 'pool/ha': 'CT-52'}

    def test_templates_are_marked_synthetic_and_anonymised(self):
        vt = [t for t in templates.all_templates() if t['id'] >= 'CT-50']
        self.assertGreaterEqual(len(vt), 12)
        for t in vt:
            self.assertIn(SYN, t['notes'], t['id'])
            self.assertIn(t['product'], ('xcpng', 'xo', 'vates'))
            self.assertTrue(t['bundle'] and t['kb'] and t['resolution'], t['id'])
            for ip in re.findall(r'(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])', repr(t['lines']) + t['issue']):
                self.assertTrue(ip.startswith('192.0.2.'), ip)

    def test_required_categories_have_bundles_that_detect(self):
        for cat, tid in self.CATEGORIES.items():
            t = templates.get(tid)
            res = analyse(tid)
            ids = [f['id'] for f in res['findings'][:8]]
            for r in t['expect_rules']:
                self.assertIn(r, ids, '%s (%s)' % (tid, cat))

    def test_cli_build_and_html_report(self):
        out = tempfile.mkdtemp(prefix='lvx_cli_')
        try:
            subprocess.run([sys.executable, '-m', 'lvx', 'templates', 'build', 'CT-59', out], cwd=ROOT, check=True, capture_output=True)
            tgz = os.path.join(out, 'CT-59.tgz')
            self.assertTrue(os.path.isfile(tgz))
            html = os.path.join(out, 'r.html')
            subprocess.run([sys.executable, '-m', 'lvx', 'analyze', tgz, '--time', '2026-03-10T10:00:00Z', '--format', 'html', '-o', html], cwd=ROOT, check=True, capture_output=True)
            with open(html, encoding='utf-8') as fh:
                txt = fh.read()
            self.assertIn('Xen Orchestra backup', txt)
            self.assertIn('Vates/XCP-ng KB research', txt)
            self.assertIn('(seen 2026-10-10)', txt)
        finally:
            shutil.rmtree(out, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
