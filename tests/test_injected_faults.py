"""End-to-end: build fault-injected bundles (tests/fault_bundles.py) and check LogLens finds and correctly ranks the planted cause."""
import os, sys, tempfile, unittest
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..'))
sys.path.insert(0, HERE)
os.environ['FB_OUT'] = tempfile.mkdtemp(prefix='lvx_fault_')
import fault_bundles as fb                                         # noqa: E402
from lvx import bundle, analyzer                                    # noqa: E402


def run(name, issue, when):
    import time, calendar
    b = bundle.open_bundle('t-' + name, os.path.join(fb.OUT, name + '.tgz'), work_base=fb.OUT)
    ts = calendar.timegm(time.strptime(when, '%Y-%m-%dT%H:%M:%SZ'))
    return analyzer.analyze(b, issue=issue, anchor=ts)


class Faults(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fb.xcp()

    def ids(self, res):
        return [f['id'] for f in res['findings']]

    def test_xcp_sr_full_is_root_of_coalesce_and_vm_start(self):
        r = run('XCP-SRFULL-01', 'VM db02 fails to start and nightly backup fails', '2026-11-20T08:10:00Z')
        ids = self.ids(r)
        self.assertEqual(ids[0], 'xcp.sr_full')
        for want in ('xcp.coalesce_stuck', 'xcp.vm_start_fail', 'xcp.sr_chain', 'xcp.xo_backup'):
            self.assertIn(want, ids)
            self.assertLess(ids.index('xcp.sr_full'), ids.index(want))


if __name__ == '__main__':
    unittest.main()
