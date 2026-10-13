# Ten synthetic cases

Compact bundles (one background line per 300 s). Upload one in the web UI, paste the issue, set the incident time shown below.

## T01 - HA pool: hosts self-fence after a management-network blip

* Bundle: `T01.tgz`
* Issue: Three hosts in an HA pool rebooted within a minute of each other and the ERP VMs were restarted on other hosts. The network team saw a short switch outage.
* Incident time: `2026-09-27T14:30:00Z`
* Expected rank 1: `xcp.ha_fence`
* Also expected: `xcp.master_unreachable`
* Root cause: HA heartbeat/statefile loss -> self-fence. Downstream: members lose the coordinator, VMs fail to start while hosts reboot.

## T02 - Storage cascade across XCP-ng and XO: SR full -> coalesce -> chain -> backup + VM start

* Bundle: `T02.tgz`
* Issue: Nightly backups started failing a week ago and today a CRM VM will not start. The NFS storage repository is nearly full.
* Incident time: `2026-09-27T14:30:00Z`
* Expected rank 1: `xcp.sr_full`
* Also expected: `xcp.coalesce_stuck`, `xcp.sr_chain`, `xcp.xo_backup`, `xcp.vm_start_fail`
* Root cause: SR out of space. Effects in order: coalesce cannot run, VHD chain grows, XO backups fail, a VM cannot start.

## T03 - iSCSI multipath storm: paths fail, the SR drops, disk I/O errors

* Bundle: `T03.tgz`
* Issue: After switch maintenance an iSCSI SR went offline and a dozen VMs froze. Storage says the array is healthy.
* Incident time: `2026-09-27T14:30:00Z`
* Expected rank 1: `xcp.multipath_fail`
* Also expected: `xcp.sr_unplugged`, `xcp.io_error`
* Root cause: all multipath paths lost. Effects: the SR cannot be plugged, reads fail with I/O errors.

## T04 - dom0 out of memory kills xapi, XO shows the host disconnected and backups fail

* Bundle: `T04.tgz`
* Issue: xe commands on xcp01 hang, Xen Orchestra shows the host as disconnected and the nightly backup did not run.
* Incident time: `2026-09-27T14:30:00Z`
* Expected rank 1: `xcp.dom0_oom`
* Also expected: `xcp.xapi_down`, `xcp.xo_backup`
* Root cause: kernel OOM killed xapi. Effects: toolstack down, XO loses the host, backup job fails.

## T05 - Leaked storage datapath after an aborted export: backups and VM start fail

* Bundle: `T05.tgz`
* Issue: Weekly backup of one VM failed and now the VM will not start on its host; its disk seems to be still in use.
* Incident time: `2026-09-27T14:30:00Z`
* Expected rank 1: `xcp.datapath_leak`
* Also expected: `xcp.xo_backup`, `xcp.vm_start_fail`
* Root cause: a VDI/datapath left attached on the host. Effects: export fails, later attach/start fails.

## T06 - dom0 disk full from log spam: xapi down and updates fail

* Bundle: `T06.tgz`
* Issue: Host xcp04 is disconnected in XO and yum updates fail. The control domain disk usage alarm fired last night.
* Incident time: `2026-09-27T14:30:00Z`
* Expected rank 1: `xcp.host_disk_full`
* Also expected: `xcp.xapi_down`, `xcp.update_fail`
* Root cause: dom0 filesystem full. Effects: xapi cannot write its database and exits, yum cannot download.

## T07 - Xen Orchestra cannot connect to the pool after a certificate change

* Bundle: `T07.tgz`
* Issue: After the certificate on the pool master was replaced, Xen Orchestra shows the pool as disconnected.
* Incident time: `2026-09-27T14:30:00Z`
* Expected rank 1: `xcp.xo_tls`
* Also expected: -
* Root cause: untrusted/self-signed certificate. A successful backup line is a benign near-miss.

## T08 - XOA update fails because the appliance disk is full

* Bundle: `T08.tgz`
* Issue: Updating the Xen Orchestra appliance fails every time with an obscure error.
* Incident time: `2026-09-27T14:30:00Z`
* Expected rank 1: `xcp.xo_disk_full`
* Also expected: `xcp.xoa_update`
* Root cause: appliance filesystem full. Effect: the updater fails.

## T09 - Rolling Pool Update stops: not enough free memory to evacuate a host

* Bundle: `T09.tgz`
* Issue: A Rolling Pool Update from XO stops on the first host and the task is stuck.
* Incident time: `2026-09-27T14:30:00Z`
* Expected rank 1: `xcp.vm_no_memory`
* Also expected: `xcp.update_fail`
* Root cause: not enough free memory to move VMs off the host. Effect: the update stops.

## T10 - Healthy pool with heavy benign noise (negative case)

* Bundle: `T10.tgz`
* Issue: Routine check after the weekend, nothing reported.
* Incident time: `2026-09-27T14:30:00Z`
* Expected rank 1: `nothing at high/critical (negative case)`
* Also expected: -
* No incident. Counts false positives: nothing at high/critical severity may be reported.
