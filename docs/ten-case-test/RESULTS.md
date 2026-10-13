# LogLens Vates - 10-case synthetic test and performance results

Run on 2026-10-13 (Python 3.13.16, 4 CPU(s), Linux-6.18.44-fc-v114-x86_64-with-glibc2.39). Each case: 14 days of background logs (one line every 15s per file, plus benign warnings/near-misses), the same signatures 12 days earlier as decoys, and a planted incident.

> **In-sample caveat.** The rules and these cases were written by the same author. The cases use fresh wording but are still approximations of real logs, so the numbers below show the pipeline works - not real-world recall. Please try real, sanitised XCP-ng / XO logs.

## Summary

| Metric | Result |
|---|---|
| Cases passed (root cause #1, secondary findings in top 8, no false high/critical, evidence line correct) | **10 / 10** |
| Root cause ranked #1 | 9 / 9 (100%) |
| Root cause within top 3 | 9 / 9 |
| Expected secondary findings found in top 8 | 15 / 15 |
| False high/critical rule findings (all cases incl. the clean negative) | 0 |
| Evidence correct (stored sample line equals the file line) | 9 / 9 |
| Lines scanned in total | 3,091,963 |
| Average noise removed by the incident window | 92.4% of lines |
| Total / slowest wall time (extract + analyse) | 24.9 s / 3.4 s |
| Average throughput | 124,275 lines/s |
| Highest peak memory (RSS, per-case process) | 101 MB |

## Per case

| # | Case | Expected root | Rank | Top rule findings | Secondary | False high | Evidence | Lines | In window | Wall s | lines/s | RSS MB | Result |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| T01 | HA pool: hosts self-fence after a management-network blip | `xcp.ha_fence` | 1 | `ha_fence`, `master_unreachable`, `vm_start_fail` | 1/1 | 0 | ok | 325,401 | 24,573 | 2.5 | 131,509 | 83 | PASS |
| T02 | Storage cascade across XCP-ng and XO: SR full -> coalesce -> chain -> backup + VM start | `xcp.sr_full` | 1 | `sr_full`, `coalesce_stuck`, `xo_backup`, `sr_chain` | 4/4 | 0 | ok | 405,831 | 30,660 | 3.2 | 125,430 | 101 | PASS |
| T03 | iSCSI multipath storm: paths fail, the SR drops, disk I/O errors | `xcp.multipath_fail` | 1 | `multipath_fail`, `sr_unplugged`, `io_error` | 2/2 | 0 | ok | 325,241 | 24,561 | 2.5 | 129,406 | 83 | PASS |
| T04 | dom0 out of memory kills xapi, XO shows the host disconnected and backups fail | `xcp.dom0_oom` | 1 | `dom0_oom`, `xo_backup`, `xapi_down` | 2/2 | 0 | ok | 406,120 | 30,655 | 3.3 | 123,005 | 101 | PASS |
| T05 | Leaked storage datapath after an aborted export: backups and VM start fail | `xcp.datapath_leak` | 1 | `datapath_leak`, `xo_backup`, `vm_start_fail` | 2/2 | 0 | ok | 406,154 | 30,564 | 3.3 | 122,144 | 101 | PASS |
| T06 | dom0 disk full from log spam: xapi down and updates fail | `xcp.host_disk_full` | 1 | `host_disk_full`, `xapi_down`, `update_fail` | 2/2 | 0 | ok | 325,689 | 24,574 | 2.6 | 123,925 | 83 | PASS |
| T07 | Xen Orchestra cannot connect to the pool after a certificate change | `xcp.xo_tls` | 1 | `xo_tls` | - | 0 | ok | 82,648 | 6,558 | 0.8 | 108,192 | 38 | PASS |
| T08 | XOA update fails because the appliance disk is full | `xcp.xo_disk_full` | 1 | `xo_disk_full`, `xoa_update` | 1/1 | 0 | ok | 82,654 | 6,626 | 0.8 | 97,657 | 38 | PASS |
| T09 | Rolling Pool Update stops: not enough free memory to evacuate a host | `xcp.vm_no_memory` | 1 | `vm_no_memory`, `update_fail` | 1/1 | 0 | ok | 325,519 | 24,630 | 2.4 | 133,978 | 83 | PASS |
| T10 | Healthy pool with heavy benign noise (negative case) | `none (negative)` | - | - | - | 0 | - | 406,706 | 30,655 | 3.4 | 121,021 | 101 | PASS |

## Scaling (case T02 at three sizes)

| Background line every | Lines scanned | Bundle MB | Wall s | lines/s | Peak RSS MB | Rank-1 correct |
|---|---|---|---|---|---|---|
| 60 s | 102,880 | 1.0 | 0.8 | 122,497 | 37 | yes |
| 15 s | 405,831 | 3.8 | 3.3 | 121,522 | 101 | yes |
| 5 s | 1,215,227 | 10.7 | 10.0 | 121,935 | 270 | yes |

Measured: 11.8x more lines (102,880 -> 1,215,227) took 11.9x the wall time and 7.2x the peak memory (37 -> 270 MB, about 0.21 KB per line). So time scales roughly linearly with the number of lines and memory grows with it; very large bundles (tens of millions of lines) have not been tested and would need a lot of RAM.

## The ten cases

**T01 - HA pool: hosts self-fence after a management-network blip**  
*Issue given to the tool:* Three hosts in an HA pool rebooted within a minute of each other and the ERP VMs were restarted on other hosts. The network team saw a short switch outage.  
*Ground truth:* Root cause: HA heartbeat/statefile loss -> self-fence. Downstream: members lose the coordinator, VMs fail to start while hosts reboot.

**T02 - Storage cascade across XCP-ng and XO: SR full -> coalesce -> chain -> backup + VM start**  
*Issue given to the tool:* Nightly backups started failing a week ago and today a CRM VM will not start. The NFS storage repository is nearly full.  
*Ground truth:* Root cause: SR out of space. Effects in order: coalesce cannot run, VHD chain grows, XO backups fail, a VM cannot start.

**T03 - iSCSI multipath storm: paths fail, the SR drops, disk I/O errors**  
*Issue given to the tool:* After switch maintenance an iSCSI SR went offline and a dozen VMs froze. Storage says the array is healthy.  
*Ground truth:* Root cause: all multipath paths lost. Effects: the SR cannot be plugged, reads fail with I/O errors.

**T04 - dom0 out of memory kills xapi, XO shows the host disconnected and backups fail**  
*Issue given to the tool:* xe commands on xcp01 hang, Xen Orchestra shows the host as disconnected and the nightly backup did not run.  
*Ground truth:* Root cause: kernel OOM killed xapi. Effects: toolstack down, XO loses the host, backup job fails.

**T05 - Leaked storage datapath after an aborted export: backups and VM start fail**  
*Issue given to the tool:* Weekly backup of one VM failed and now the VM will not start on its host; its disk seems to be still in use.  
*Ground truth:* Root cause: a VDI/datapath left attached on the host. Effects: export fails, later attach/start fails.

**T06 - dom0 disk full from log spam: xapi down and updates fail**  
*Issue given to the tool:* Host xcp04 is disconnected in XO and yum updates fail. The control domain disk usage alarm fired last night.  
*Ground truth:* Root cause: dom0 filesystem full. Effects: xapi cannot write its database and exits, yum cannot download.

**T07 - Xen Orchestra cannot connect to the pool after a certificate change**  
*Issue given to the tool:* After the certificate on the pool master was replaced, Xen Orchestra shows the pool as disconnected.  
*Ground truth:* Root cause: untrusted/self-signed certificate. A successful backup line is a benign near-miss.

**T08 - XOA update fails because the appliance disk is full**  
*Issue given to the tool:* Updating the Xen Orchestra appliance fails every time with an obscure error.  
*Ground truth:* Root cause: appliance filesystem full. Effect: the updater fails.

**T09 - Rolling Pool Update stops: not enough free memory to evacuate a host**  
*Issue given to the tool:* A Rolling Pool Update from XO stops on the first host and the task is stuck.  
*Ground truth:* Root cause: not enough free memory to move VMs off the host. Effect: the update stops.

**T10 - Healthy pool with heavy benign noise (negative case)**  
*Issue given to the tool:* Routine check after the weekend, nothing reported.  
*Ground truth:* No incident. Counts false positives: nothing at high/critical severity may be reported.

## How the test works

1. `python tests/ten_case_benchmark.py run` builds each bundle deterministically (`tests/vates_gen.py` noise + the planted lines), packs it as `.tgz`, and runs the analysis **in a separate process** (so peak memory is per case).
2. The analysis uses the real code path: extract the archive, scan every log file, window the lines around the incident, rank findings, attach KB research.
3. A case **passes** when the expected root-cause rule is rank 1, every expected secondary rule is in the top 8, no *other* rule finding at high/critical severity appears, and the first stored evidence line equals the real line in the file. The negative case passes when no rule finding at high/critical severity appears.
4. Rules allowed as extra findings in a case (benign companions such as a VM start failure) are listed per case in the script and are not counted as false positives; anything else at high/critical is.
5. `python tests/ten_case_benchmark.py build OUT` writes compact versions of the ten bundles (one line per 300 s) as `.tgz` for trying them in the web UI; they are also in `examples/ten-case-test/`.

## Limits

* In-sample: see the caveat above. Held-out wording was used, but by the same author as the rules.
* Timings come from one machine and one run; the sandbox is not a benchmark lab. Throughput depends on disk, CPU and Python version.
* Real XCP-ng logs have more variety (long Python tracebacks, rotated `.gz` files, multi-line messages) than these synthetic ones.
* Total run time of the script: 87 s.
