# Example bundles

Synthetic bundles for trying LogLens Vates (invented hostnames, 192.0.2.x addresses; no real customer data; log wording approximated from public search summaries).

1. `python -m lvx serve` and open the printed address.
2. Upload a bundle from `vates/`, paste the issue text from `vates/CASES.txt`, set the incident time to `2026-03-10T10:00:00Z`, Analyze, and compare with `vates/reference-reports/`.
3. On the top finding use *Show log context*, *open in viewer* and Confirm / Reject / Unsure. `vates/screenshots/` shows the flow.

| Bundle | Scenario |
|---|---|
| 1-CT-59 | Xen Orchestra: nightly delta backups fail with VDI_IO_ERROR |
| 2-CT-60 | Xen Orchestra cannot connect to a pool (self-signed / replaced certificate) |
| 3-CT-50 | XCP-ng host: dom0 filesystem full, xapi will not come back |
| 4-CT-53 | SR almost full -> coalesce stuck -> VM will not start |
| 5-CT-56 | VM will not start: not enough free host memory |
| 6-CT-52 | HA pool: hosts self-fence after a management-network outage |

More: `python -m lvx templates list` and `python -m lvx templates build CT-xx OUT_DIR`.
