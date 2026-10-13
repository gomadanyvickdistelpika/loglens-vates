"""Regenerates lvx/case_templates.json - SYNTHETIC scenarios (CT-50..) built from public Vates / XCP-ng / Xen Orchestra search summaries.

Rules for this file (privacy / honesty):
  * no customer/company/person names, no case numbers, no real hostnames/IPs/emails - everything here is invented
    (lab.example hostnames, 192.0.2.x addresses).  tests/test_templates.py enforces this.
  * `lines` are SYNTHETIC log lines approximated from error names and phrases in search summaries.  Never present them as real logs.
  * cause/resolution text is only what the search summaries stated (or an explicitly labelled generic check).
  * kb = public pages that actually appeared in search results (title + URL + date seen); the page text was not read.

Run:  python tools/build_case_templates.py
"""
import json
import os

T = []


def kb(url, title, role='cited', seen='2026-10-10'):
    assert str(url).startswith('https://') and title, url
    return dict(id=str(url), title=title, role=role, seen=seen)      # date the page appeared in a web search (summary only) or was fetched


def tpl(id, title, product, version, issue, evidence, expect, lines, cause='', resolution=(), kbs=(), match=None,
        notes='', bundle=True, extra_files=None, expect_snapshot=False, noise='auto'):
    T.append(dict(id=id, title=title, product=product, version=version, issue=issue, evidence=evidence, bundle=bundle,
                  expect_rules=list(expect), expect_snapshot=expect_snapshot, match=match, noise=noise,
                  lines=[list(l) for l in lines], extra_files=extra_files or {},
                  cause=cause, resolution=list(resolution), kb=list(kbs), notes=notes))


# ============================================================================= Vates: XCP-ng / Xen Orchestra (CT-50..)
VN = 'SYNTHETIC SCENARIO built from public Vates forum/docs search summaries, not a resolved support case. Log wording is approximated from error names and phrases seen in those summaries, not copied from real logs; the pages themselves were not read in full.'
XH = 'var/log/xensource.log'
SMLOG = 'var/log/SMlog'
DMN = 'var/log/daemon.log'
MSGS = 'var/log/messages'
KERN = 'var/log/kern.log'
XHA = 'var/log/xha.log'
XOJ = 'xo/journalctl-xo-server.txt'
XOU = 'xo/journalctl-xoa-updater.txt'
XOI = 'xo/xo-install.log'
FM = 'https://xcp-ng.org/forum/topic/'
DOC = 'https://docs.xcp-ng.org/'
XOD = 'https://xen-orchestra.com/docs/'

tpl('CT-50', 'XCP-ng host: dom0 filesystem full, xapi will not come back after a toolstack restart', 'xcpng', '8.x',
    'Host xcp01 is unreachable in Xen Orchestra. xe commands fail with "Connection refused" and the control-domain disk usage alarm fired earlier.',
    'mixed', ['xcp.host_disk_full', 'xcp.xapi_down'], [
        (-5400, XH, '{s} xcp01 xapi: [error|xcp01.lab.example|3321 ||xapi] Could not write database: No space left on device', 'typical'),
        (-5300, MSGS, '{s} xcp01 xcp-ng: Disk Usage for Control Domain on server xcp01.lab.example has reached 98%', 'typical'),
        (-5000, DMN, '{s} xcp01 xapi: Connection refused (calling connect )', 'typical'),
        (-4800, XH, '{s} xcp01 xe-toolstack-restart: [warning] xapi did not come back after the restart; /var/log is 100% full', 'typical')],
    cause='Per the forum summaries a full /var/log (or /) stops xapi and logging; one thread needed a host reboot even after space was freed. Typical sources named: SR.scan log spam on the pool master and old guest tools.',
    resolution=['df -h and du -xh /var/log | sort -h | tail to find what filled the partition.', 'Free the space (rotate/remove oversized logs).', 'If the log spam came from frequent SR scans on the pool master, lower the rate: xe host-param-set other-config:auto-scan-interval=120 uuid=<host uuid> (forum report).',
                'Restart the toolstack (xe-toolstack-restart; check xe task-list first) or reboot the host if xapi still does not start.'],
    kbs=[kb(FM + '3028/logs-partition-full', 'Logs Partition Full', 'primary'), kb(FM + '4734/toolstack-reboot-and-100-disk-usage-bad-idea', 'toolstack-reboot and 100% disk usage. Bad idea', 'secondary'),
         kb(FM + '11630/log_fs_usage-var-log-directory-on-pool-master-filling-up-constantly/13', 'log_fs_usage / /var/log directory on pool master filling up constantly', 'secondary')],
    match=r'No space left|Control Domain|Connection refused|var/log', notes=VN)

tpl('CT-51', 'XCP-ng pool: member host cannot reach the pool master after a power event', 'xcpng', '8.x',
    'After a power event the member host xcp02 reports that the pool master is unreachable and Xen Orchestra lost the pool. The master xcp01 was rebooted.',
    'mixed', ['xcp.master_unreachable'], [
        (-3000, XH, '{s} xcp02 xapi: [error|xcp02.lab.example|88 ||xapi] Unable to contact the pool master xcp01.lab.example (192.0.2.11): connection timed out', 'typical'),
        (-2900, XH, '{s} xcp02 xapi: [error|xcp02.lab.example|90 ||xapi] Lost contact with the pool master; entering emergency mode', 'typical'),
        (-2800, DMN, '{s} xcp02 xapi: [ warn|xcp02.lab.example|91 ||xapi] HOST_IS_SLAVE: this host cannot execute the request, the master is 192.0.2.11', 'typical')],
    cause='Per the forum/docs summaries: the member cannot reach the coordinator. Community reports resolved it with an emergency network reset on the affected host or on the master; if the master is truly dead a survivor is promoted manually.',
    resolution=['Check whether the master is alive (xapi on xcp01, management bond/VLAN) before promoting anything.', 'If HA is enabled: xe host-emergency-ha-disable force=true, then xe-toolstack-restart.',
                'Community fix: emergency network reset on the affected host (after a toolstack restart on the master did not help), then reboot the other members once the master is back.',
                'Only if the master is dead: xe pool-emergency-transition-to-master uuid=<host uuid> on a survivor, then xe pool-emergency-reset-master master-address=<new master> on the others; later xe host-forget the old master.'],
    kbs=[kb(DOC + 'troubleshooting/troubleshooting-ha/', 'High availability (HA) - XCP-ng troubleshooting docs', 'primary'), kb(FM + '4075/pool-master-down-what-steps-need-done-next', 'Pool master down, what steps need done next?', 'secondary'),
         kb(FM + '8694/hosts-in-a-pool-have-gone-offline-after-reboot', 'Hosts in a pool have gone offline after reboot', 'secondary')],
    match=r'pool master|coordinator|emergency|HOST_IS_SLAVE', notes=VN)

tpl('CT-52', 'XCP-ng HA: hosts self-fence and reboot after a short management-network outage', 'xcpng', '8.x',
    'Hosts in an HA-enabled pool rebooted and their VMs were restarted elsewhere. The network team reports a short switch outage on the management VLAN.',
    'mixed', ['xcp.ha_fence', 'xcp.master_unreachable'], [
        (-1800, XHA, '{s} xcp03 xhad: [warning] heartbeat from host xcp01 lost on the management interface (xha)', 'typical'),
        (-1790, XHA, '{s} xcp03 xhad: statefile access failed: heartbeat disk unreachable', 'typical'),
        (-1780, XHA, '{s} xcp03 xhad: Could not join the liveset: the HA daemon could not access the heartbeat disk', 'typical'),
        (-1770, XHA, '{s} xcp03 xhad: host xcp03.lab.example self-fencing: initiating hard reboot', 'typical'),
        (-1500, XH, '{s} xcp02 xapi: [error|xcp02.lab.example|55 ||xapi] Lost contact with the pool master', 'typical')],
    cause='Per the docs summary: a host that loses both the network heartbeat (UDP on the management interface) and the storage heartbeat (ha-statefile) within the timeout (default 60 s) treats itself as problematic and does a hard reboot (self-fence).',
    resolution=['Read /var/log/xha.log on each host to see who self-fenced and who asked whom to reboot.', 'Fix the management network / bond path and confirm every host can reach the heartbeat SR.', 'Docs recommend at least 3 hosts; with two, a lost link can get hosts fenced.',
                'To stabilise while investigating: xe host-emergency-ha-disable force=true and xe-toolstack-restart; re-enable with xe pool-ha-enable heartbeat-sr-uuid=<sr uuid>.'],
    kbs=[kb(DOC + 'management/ha/', 'High availability - XCP-ng docs', 'primary'), kb('https://xcp-ng.org/blog/2024/08/22/xcp-ng-high-availability-a-guide/', 'XCP-ng High Availability: a guide', 'secondary'),
         kb(FM + '12483/ha-causes-reboot-of-xcp-ng-nodes', 'HA causes reboot of xcp-ng nodes', 'secondary')],
    match=r'xha|fenc|liveset|heartbeat', notes=VN)

tpl('CT-53', 'XCP-ng storage: SR almost full, coalesce stuck, then a VM will not start', 'xcpng', '8.x',
    'A VM will not start after a backup job. The NFS storage repository is almost full and backups began failing earlier this week.',
    'mixed', ['xcp.sr_full', 'xcp.coalesce_stuck', 'xcp.vm_start_fail', 'xcp.sr_chain'], [
        (-7200, SMLOG, '{s} xcp01 SM: [21433] Insufficient space on SR 0a1b2c3d-1111-2222-3333-444455556666: SR_BACKEND_FAILURE_44', 'typical'),
        (-5400, SMLOG, '{s} xcp01 SMGC: [30112] Unable to coalesce 8f7e6d5c: no space to leaf-coalesce, the SR is full', 'typical'),
        (-5300, SMLOG, '{s} xcp01 SMGC: [30112] UNDO LEAF-COALESCE of 8f7e6d5c', 'typical'),
        (-3600, SMLOG, '{s} xcp01 SM: [22001] Raising exception: the snapshot chain is too long (SR_BACKEND_FAILURE_109)', 'typical'),
        (-600, XH, '{s} xcp01 xapi: [error|xcp01.lab.example|7001 ||xenops] Failed to start the VM app01: HVM boot failed (the VDI cannot be activated, the SR has no free space)', 'typical')],
    cause='Per the summaries: coalesce (which frees snapshot space) runs after a snapshot is deleted and can fail when the SR lacks free space, which keeps the SR full and lets VDI chains grow; SR_BACKEND_FAILURE_44 means insufficient space. The VM failing to start is the downstream symptom.',
    resolution=['Free space on the SR first: move VMs/disks to another SR (also forces a coalesce) or delete old snapshots, keeping the base and latest.', 'Rescan the SR to restart the garbage collector; shut the VMs down before rescanning for a better chance of offline coalesce (user report).',
                'Keep roughly 30% free (XO docs summary); thin-provisioned local ext is more forgiving than thick LVM (Vates staff in a thread).', 'Then start the VM and review backup schedules that created the snapshots.'],
    kbs=[kb(XOD + 'backup_troubleshooting.html', 'Backup troubleshooting - Xen Orchestra docs', 'primary'), kb(FM + '10489/issue-with-sr-and-coalesce/21?page=1', 'Issue with SR and coalesce', 'secondary'),
         kb(FM + '11226/some-backups-failing', 'Some backups failing', 'secondary')],
    match=r'Insufficient space|SR_BACKEND_FAILURE|coalesce|HVM boot', notes=VN)

tpl('CT-54', 'XCP-ng / XO: delta backups skipped to protect a long VDI chain, coalesce timing out', 'vates', '8.x',
    'Delta backups of one VM fail or are skipped. Xen Orchestra reports an unhealthy VDI chain and the SR Advanced tab shows a growing "VDI to coalesce" count.',
    'mixed', ['xcp.coalesce_stuck', 'xcp.sr_chain', 'xcp.xo_backup'], [
        (-4000, SMLOG, '{s} xcp01 SMGC: [4411] Exception while coalescing VDI 11aa22bb: leaf-coalesce timed out', 'typical'),
        (-3900, SMLOG, '{s} xcp01 SMGC: [4411] UNDO LEAF-COALESCE of 11aa22bb', 'typical'),
        (-3000, SMLOG, '{s} xcp01 SM: [4502] Raising exception: the snapshot chain is too long (SR_BACKEND_FAILURE_109)', 'typical'),
        (-1800, XOJ, '{s} xo01 xo-server[771]: 2026-03-10T09:30:01.000Z xo:backups:worker WARN Backup skipped to protect VDI chain: unhealthy VDI chain on SR nfs-sr01', 'typical')],
    cause='Per the XO docs summary: XCP-ng caps a VHD chain at 30 elements; the error is a protection and a stuck coalesce is the usual cause. A corrupted VDI can stop the garbage collector (Vates engineer in a thread).',
    resolution=['Check the "VDI to coalesce" count on the SR Advanced tab in XO; if it does not fall over time, grep /var/log/SMlog for exceptions and UNDO LEAF-COALESCE.', 'ps axf | grep vhd shows whether a coalesce is running; rescan the SR to trigger one.',
                'As a last resort migrate the VM disks to another SR to force a coalesce (XO docs).', 'A 8.3 leaf-coalesce timeout workaround (LIVE_LEAF_COALESCE_* in cleanup.py) exists in a forum thread but is unofficial; back up first.'],
    kbs=[kb(XOD + 'backup_troubleshooting.html', 'Backup troubleshooting - Xen Orchestra docs', 'primary'), kb(FM + '10271/sr-garbage-collection-running-permanently', 'SR Garbage Collection running permanently', 'secondary'),
         kb(FM + '4177/error-sr_backend_failure_109-the-snapshot-chain-is-too-long', 'Error: SR_BACKEND_FAILURE_109(, The snapshot chain is too long, )', 'secondary')],
    match=r'coalesce|chain', notes=VN)

tpl('CT-55', 'XCP-ng storage: iSCSI SR will not re-attach after a host reboot', 'xcpng', '8.x',
    'After a host reboot the iSCSI storage repository shows as unplugged and the VMs on it will not start. Plugging the PBD fails.',
    'mixed', ['xcp.sr_unplugged'], [
        (-2400, XH, '{s} xcp02 xapi: [error|xcp02.lab.example|120 ||xapi] PBD_PLUG_FAILED: the SR iscsi-sr01 could not be attached', 'typical'),
        (-2390, SMLOG, '{s} xcp02 SM: [8812] iscsiadm login failed: iSCSI login to 192.0.2.50:3260 timed out', 'typical'),
        (-2380, SMLOG, '{s} xcp02 SM: [8812] SR is not available: /dev/disk/by-scsid/360000000000000000e00000000010001 does not exist', 'typical'),
        (-2300, KERN, '{s} xcp02 kernel: nfs: server 192.0.2.60 not responding, timed out', 'typical')],
    cause='Per the summaries no single cause: an iSCSI login/discovery problem (CHAP), a missing /dev/disk/by-scsid device, a hung iscsid, stale NFS mounts, or damaged LVM metadata on a local drive.',
    resolution=['Run xe pbd-plug while watching xensource.log and SMlog.', 'iSCSI: check iscsiadm -m session, run sendtargets discovery first (it made pbd-plug work once, but the failure returned at every reboot), check whether iscsid is hung.', 'NFS: unmount the stale path then reconnect; consider hard mount options.',
                'The iSCSI-after-reboot case in the GitHub issue had no confirmed permanent fix in the search summary.'],
    kbs=[kb(FM + '10903/how-to-re-attach-an-sr', 'How to Re-attach an SR', 'primary'), kb('https://github.com/xcp-ng/xcp/issues/260', 'After upgrade to 8.0: iSCSI connection fails after reboot · Issue #260 · xcp-ng/xcp', 'secondary'),
         kb(FM + '5981/unstable-nfs-sr-mounts', 'Unstable NFS SR mounts', 'secondary')],
    match=r'PBD|iscsi|by-scsid|nfs', notes=VN)

tpl('CT-56', 'XCP-ng VM: a 16 GB VM will not start although the host seems to have free RAM', 'xcpng', '8.x',
    'Starting a large VM on host xcp02 from Xen Orchestra fails with a "not enough free memory" error although the host seems to have free RAM.',
    'mixed', ['xcp.vm_no_memory', 'xcp.vm_start_fail'], [
        (-1500, XH, '{s} xcp02 xapi: [error|xcp02.lab.example|2201 ||xapi] VM.start failed: HOST_NOT_ENOUGH_FREE_MEMORY (required 17179869184, available 12884901888)', 'typical'),
        (-1490, XH, '{s} xcp02 xapi: [error|xcp02.lab.example|2201 ||xapi] Unable to start the VM db01: not enough host memory', 'typical')],
    cause='Per the summaries: the memory is already committed (dynamic-max of all running VMs plus dom0), or state is stale after migrations; a toolstack restart fixed one case.',
    resolution=['Compare xe host-list params=memory-free with xe vm-compute-maximum-memory for the VM.', 'Restart the toolstack (or reboot the host) and retry; consider static memory instead of a dynamic range.', 'On a smaller second host, dom0 memory also reduces what a 16 GB VM can use.'],
    kbs=[kb(FM + '3991/not-enough-server-memory-when-start-vm', 'Not enough server memory when start VM', 'primary'), kb(FM + '9929/xcp-ng-host-ram', 'xcp-ng host RAM', 'secondary')],
    match=r'HOST_NOT_ENOUGH_FREE_MEMORY|not enough', notes=VN)

tpl('CT-57', 'XCP-ng VM: live storage migration of a busy VM fails with MIRROR_FAILED', 'xcpng', '8.x',
    'Live migration (with storage) of a large, write-heavy database VM fails after many hours and Xen Orchestra reports MIRROR_FAILED.',
    'mixed', ['xcp.migrate_fail'], [
        (-1200, XH, '{s} xcp01 xapi: [error|xcp01.lab.example|9100 ||xapi] Storage migration: MIRROR_FAILED, the block mirror could not keep up with the writes of the VM', 'typical'),
        (-1190, XH, '{s} xcp01 xapi: [error|xcp01.lab.example|9100 ||xapi] VM.migrate_send failed: VM_MIGRATE_FAILED', 'typical')],
    cause='Per the forum summary (Vates CEO): a live storage migration replicates blocks while the VM runs; if the VM writes faster than the mirror copies, the migration fails.',
    resolution=['Use warm migration for very large or write-heavy VMs (suggested in the thread).', 'Read /var/log/xensource.log on the source host for the underlying error.', 'A VM left looking running after the failure: xe vm-reset-powerstate or a toolstack restart (other threads).'],
    kbs=[kb(FM + '9801/live-migration-fails-mirror_failed', 'Live Migration Fails: MIRROR_FAILED', 'primary'), kb(FM + '6496/vm-migrate-problem', 'VM Migrate problem', 'secondary')],
    match=r'MIRROR_FAILED|VM_MIGRATE_FAILED', notes=VN)

tpl('CT-58', 'XCP-ng update: Rolling Pool Update stops on the second host (yum error, evacuation blocked)', 'xcpng', '8.x',
    'A Rolling Pool Update started from Xen Orchestra stopped on the second host. The task is stuck and yum reports errors.',
    'mixed', ['xcp.update_fail', 'xcp.vm_no_memory'], [
        (-4000, DMN, '{s} xcp02 yum: Cannot retrieve repository metadata (repomd.xml) for repository xcp-ng-updates: HTTP Error 500', 'typical'),
        (-3900, DMN, '{s} xcp02 yum: Transaction check error: incomplete transactions found', 'typical'),
        (-3500, XH, '{s} xcp01 xapi: [error|xcp01.lab.example|4400 ||xapi] host.evacuate failed: CANNOT_EVACUATE_HOST (VM app02 cannot be migrated: HOST_NOT_ENOUGH_FREE_MEMORY)', 'typical')],
    cause='Per the summaries: repository mirror HTTP 500 errors, stale or incomplete yum transactions, backups running during the RPU, and, with HA enabled, HOST_NOT_ENOUGH_FREE_MEMORY during evacuation.',
    resolution=['Clean up incomplete yum transactions and run yum clean all, then update again.', 'Disable HA and scheduled backups/replication before a rolling pool update.', 'Manual fallback from forum staff: on each host yum update with the xcp-ng-base and xcp-ng-updates repos, migrate VMs away, reboot, repeat.',
                'CANNOT_EVACUATE_HOST caused by CPU features: shut the VM down and boot it again.'],
    kbs=[kb(FM + '9501/rolling-pool-update-failed', 'Rolling Pool Update Failed', 'primary'), kb(DOC + 'management/updates/', 'Updates - XCP-ng docs', 'secondary'),
         kb(FM + '12136/rpu-failure-on-8.3-yum-https-500-error-for-xo-lite-package-hung-task', 'RPU Failure on 8.3: Yum HTTPS 500 Error for xo-lite package (Hung Task)', 'secondary')],
    match=r'yum|repository|evacuate|EVACUATE', notes=VN)

tpl('CT-59', 'Xen Orchestra: scheduled delta backups to an NFS remote fail with VDI_IO_ERROR', 'xo', 'XO',
    'Scheduled delta backups from Xen Orchestra to an NFS remote fail every night with VDI_IO_ERROR (Device I/O errors).',
    'mixed', ['xcp.xo_backup'], [
        (-28000, XOJ, '{s} xo01 xo-server[771]: 2026-03-10T02:14:09.512Z xo:backups:worker ERROR Backup job nightly-delta failed: VDI_IO_ERROR(Device I/O errors)', 'typical'),
        (-27990, XOJ, '{s} xo01 xo-server[771]: 2026-03-10T02:14:10.002Z xo:backups:worker WARN remote nfs-backup01 was disconnected (ESTALE) during the export', 'typical'),
        (-27900, SMLOG, '{s} xcp01 SM: [5521] VDI_IO_ERROR: reading the VHD of VM db01 failed', 'typical')],
    cause='Per the XO docs summary: VDI_IO_ERROR comes from the host (dom0), not XO; the host could not read the disk during the HTTP export. Named causes: corrupted VDI or a race during snapshots, a too-slow SR, a long job timeout with a slow remote.',
    resolution=['grep -i error /var/log/SMlog on the host for coalesce or VDI corruption.', 'Check the job timeout and whether jobs overlap.', 'For an NFS remote a forum thread suggests a hard mount or adjusted soft timeout/retries (the pipe to the remote closed early and left a partial VHD).'],
    kbs=[kb(XOD + 'backup_troubleshooting.html', 'Backup troubleshooting - Xen Orchestra docs', 'primary'), kb('https://github.com/vatesfr/xen-orchestra/issues/3242', '[Backup Ng deltaBackup] VDI_IO_ERROR(Device I/O errors) · Issue #3242 · vatesfr/xen-orchestra', 'secondary'),
         kb(FM + '2991/vdi_io_error-device-i-o-errors-when-you-run-scheduled-backup/55', 'VDI_IO_ERROR(Device I/O errors) when you run scheduled backup', 'secondary')],
    match=r'VDI_IO_ERROR|remote', notes=VN)

tpl('CT-60', 'Xen Orchestra cannot connect to a pool after its host certificate was replaced (TLS error)', 'xo', 'XO',
    'After the certificate on the pool master was replaced, Xen Orchestra shows the pool as disconnected with a TLS error.',
    'mixed', ['xcp.xo_tls'], [
        (-900, XOJ, '{s} xo01 xo-server[771]: 2026-03-10T09:45:11.002Z xo:xo-mixins:xen-servers WARN server 192.0.2.21 connection failed: DEPTH_ZERO_SELF_SIGNED_CERT', 'typical'),
        (-880, XOJ, '{s} xo01 xo-server[771]: 2026-03-10T09:45:41.002Z xo:xo-mixins:xen-servers WARN server 192.0.2.21 connection failed: UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'typical')],
    cause='Per the summaries: since a 5.8.x release XO refuses to connect to a host whose certificate is invalid (self-signed or expired) unless that is explicitly allowed; the XCP-ng hosts own certificates are managed with xe commands on every host of the pool.',
    resolution=['Verify the new certificate, then either install a certificate XO trusts on every pool host or accept it via the warning/toggle in the XO server settings.', 'Plain HTTP also works but sends all traffic unencrypted.', 'Expired appliance certificate: regenerate cert.pem/key.pem with openssl and restart xo-server (docs summary).'],
    kbs=[kb('https://xen-orchestra.com/blog/improving-security-in-xen-orchestra/', 'Improving security in Xen Orchestra', 'primary'), kb(XOD + 'troubleshooting.html', 'Troubleshooting - Xen Orchestra docs', 'secondary')],
    match=r'SELF_SIGNED|UNABLE_TO_VERIFY|certificate', notes=VN)

tpl('CT-61', 'Xen Orchestra from sources: yarn build fails (node version / native module)', 'xo', 'XO',
    'After pulling the latest Xen Orchestra sources, yarn build fails and xo-server does not start.',
    'mixed', ['xcp.xo_build'], [
        (-2000, XOI, '{s} xo01 xo-install[1201]: error xo-server: The engine "node" is incompatible with this module. Expected version ">=14.5". Got "12.20.2"', 'typical'),
        (-1990, XOI, '{s} xo01 xo-install[1201]: error Found incompatible module.', 'typical'),
        (-1900, XOI, '{s} xo01 xo-install[1201]: gyp ERR! build error', 'typical')],
    cause='Per the search summaries: the node version does not satisfy the module engine requirement (the example in the summary was Expected ">=14.5", Got "12.20.2"), or native modules fail to compile on an unsupported node.',
    resolution=['Install a node version that satisfies the engine requirement named in the error.', 'Clean rebuild per the docs: remove node_modules, run yarn, then yarn build.', 'If a recent commit broke the build, check out a known-good commit (issue report).'],
    kbs=[kb('https://docs.xen-orchestra.com/getting-started/install-from-sources', 'Installing XO from source', 'primary'), kb('https://github.com/ronivay/XenOrchestraInstallerUpdater/issues/62', 'Build fails with error · Issue #62 · ronivay/XenOrchestraInstallerUpdater', 'secondary')],
    match=r'engine|gyp|node', notes=VN)

tpl('CT-62', 'XOA update fails: updater cannot reach xen-orchestra.com (TLS-intercepting proxy)', 'xo', 'XO',
    'Updating the Xen Orchestra Appliance from the Updates page fails. A transparent proxy was recently introduced.',
    'mixed', ['xcp.xoa_update'], [
        (-1500, XOU, '{s} xoa xoa-updater[412]: ERROR unable to reach xen-orchestra.com: self signed certificate in certificate chain', 'typical'),
        (-1490, XOU, '{s} xoa xoa-updater[412]: ERROR upgrade failed, see xoa check', 'typical')],
    cause='Per the XO docs summary: proxies often break the updater with SSL/TLS errors; other named causes are a corrupted or missing package, no access to xen-orchestra.com and nodejs.org on 443, and a missing registration.',
    resolution=['Run xoa check and journalctl -u xoa-updater -f -n 50 while reproducing.', 'Allow the proxy to pass xen-orchestra.com and nodejs.org untouched, or (lower security) set NODE_TLS_REJECT_UNAUTHORIZED=0 in /etc/xo-appliance/env and restart xoa-updater.', 'Delete /var/lib/xoa-updater/update.json and run xoa-updater --upgrade for a fresh download.'],
    kbs=[kb('https://docs.xen-orchestra.com/getting-started/troubleshooting', 'Troubleshooting - Xen Orchestra docs', 'primary'), kb('https://xen-orchestra.com/docs/updater.html', 'Updates - Xen Orchestra docs', 'secondary')],
    match=r'xoa-updater|xen-orchestra', notes=VN)


tpl('CT-63', 'Xen Orchestra: update and nightly backups fail with ENOSPC (appliance or remote out of space)', 'xo', 'XO',
    'Updating Xen Orchestra fails with "ENOSPC: no space left on device" and the nightly backup job starts failing as well.',
    'mixed', ['xcp.xo_disk_full'], [
        (-3000, XOI, '{s} xo01 xo-install[1301]: error ENOSPC: no space left on device, write', 'typical'),
        (-2000, XOJ, '{s} xo01 xo-server[771]: 2026-03-10T09:26:40.000Z xo:backups:worker ERROR Backup job nightly failed: ENOSPC: no space left on device, write', 'typical'),
        (-1990, XOJ, '{s} xo01 xo-server[771]: 2026-03-10T09:26:50.000Z xo:backups:worker ERROR remote nfs-backup01 is full', 'typical')],
    cause='Only the thread titles were seen in search results (an XO update failing with ENOSPC; a backup error although space seemed available); the article text was not read, so no documented cause is claimed.',
    resolution=['Generic check, not taken from the cited threads: df -h on the XO appliance and on the backup remote, free space, then rerun the failed update or job.'],
    kbs=[kb(FM + '7246/xen-orchestra-update-failed-error-enospc-no-space-left-on-device', 'Xen Orchestra Update Failed - Error: ENOSPC: no space left on device', 'primary'),
         kb(FM + '5788/backup-error-with-space-available', 'Backup error with space available', 'secondary')],
    match=r'ENOSPC|no space left|is full', notes=VN)

# ---- storage / kernel scenarios from the review of the public Fohdeesha/xcp-stuff health check (page text read 2026-10-13) ----
XS = 'https://github.com/Fohdeesha/xcp-stuff'
XS_T = 'Fohdeesha/xcp-stuff: XCP-ng / XOA health check and repair scripts (README, src/checks.py, src/config.py read)'
VN2 = VN + ' This scenario also draws on the public Fohdeesha/xcp-stuff repo (GPL-3.0), whose README, src/checks.py and src/config.py were read on 2026-10-13.'

tpl('CT-64', 'XCP-ng storage: array LUN change, multipath paths fail, the iSCSI SR drops after switch maintenance', 'xcpng', '8.x',
    'After switch maintenance an iSCSI storage repository on host xcp02 went offline and its VMs froze.',
    'mixed', ['xcp.lun_change', 'xcp.multipath_fail', 'xcp.sr_unplugged'], [
        (-3000, KERN, '{s} xcp02 kernel: scsi 3:0:0:1: Warning! Received an indication that the LUN assignments on this target have changed. The Linux SCSI layer does not automatically remap LUN assignments.', 'typical'),
        (-2400, KERN, '{s} xcp02 kernel: device-mapper: multipath: Failing path 8:32.', 'typical'),
        (-2390, MSGS, '{s} xcp02 multipathd[812]: mpatha: remaining active paths: 0', 'typical'),
        (-2300, SMLOG, '{s} xcp02 SM: [8812] SR is not available: /dev/disk/by-scsid/360000000000000000e00000000010001 does not exist', 'typical')],
    cause="Per the read of the community health check: it watches kern.log for the LUN-assignments-changed message and for \"device-mapper: multipath: Failing path\", and flags maps with no usable path or path counts that differ between hosts. Link between them and the SR dropping is this scenario's assumption, not stated in the repo.",
    resolution=['Check multipath -ll on every host: a map with no usable path, or path counts that differ between hosts.', 'Verify with the storage team whether the LUN mapping was changed on purpose before re-plugging the SR.'],
    kbs=[kb(XS, XS_T, 'primary', '2026-10-13'), kb(FM + '10903/how-to-re-attach-an-sr', 'How to Re-attach an SR', 'secondary')],
    match=r'multipath|LUN assignments|by-scsid', notes=VN2)

tpl('CT-65', 'XCP-ng storage: leaked datapath after an aborted backup, later attaches and backups fail', 'vates', '8.3',
    'Nightly backups of one VM fail and the VM will not start again on host xcp01 after a failed export; its disk shows as still in use.',
    'mixed', ['xcp.datapath_leak', 'xcp.xo_backup', 'xcp.vm_start_fail'], [
        (-3000, SMLOG, '{s} xcp01 SM: [30112] VDI 6b5a4c3d is not detached cleanly, still open on host', 'typical'),
        (-2990, SMLOG, '{s} xcp01 SM: [30113] Failed to lock /var/lock/sm/0a1b2c3d/sr on first attempt, blocked by PID 4411', 'typical'),
        (-2980, SMLOG, '{s} xcp01 SM: [30113] tap.deactivate: Warning, No such Tapdisk(minor=5)', 'typical'),
        (-2970, XH, '{s} xcp01 xapi: [error|xcp01.lab.example|9901 ||storage_access] Illegal_transition: Attached -> Activated', 'typical'),
        (-2000, XOJ, '{s} xo01 xo-server[771]: 2026-03-10T09:26:40.000Z xo:backups:worker ERROR Backup job nightly failed: VDI_IO_ERROR(Device I/O errors)', 'typical'),
        (-600, XH, '{s} xcp01 xapi: [error|xcp01.lab.example|9944 ||xapi] Failed to start the VM web07: the VDI cannot be attached on this host', 'typical')],
    cause='Per the read of the community storage-state-fixer.py: dead dom0 datapaths, stale dom0 VBDs, paused or wedged tapdisks and stuck GC flags make exports, backups and VBD unplugs fail; with other datapaths present xapi refuses the state change (Illegal_transition), the VDI is marked leaked and later attaches on that host fail. The tool is for XCP-ng 8.3 only.',
    resolution=['Identify the VDI and tapdisk (tap-ctl list) and confirm no VM really uses it before touching anything.', 'The third-party storage-state-fixer.py reports what it found and changes things only after you type yes (it restarts xapi on that host; HA is turned off and on around it): read it and test on a lab host first.'],
    kbs=[kb(XS, XS_T, 'primary', '2026-10-13')], match=r'detached cleanly|still open|blocked by PID|No such Tapdisk|Illegal_transition|VDI_IO_ERROR|Failed to start', notes=VN2)

tpl('CT-66', 'XCP-ng host: dom0 OOM-kills xapi, xe commands time out and XO shows the host disconnected', 'xcpng', '8.x',
    'xe commands on host xcp01 time out and Xen Orchestra shows the host as disconnected; the host has been up for months.',
    'mixed', ['xcp.dom0_oom', 'xcp.xapi_down'], [
        (-2400, KERN, '{s} xcp01 kernel: xapi invoked oom-killer: gfp_mask=0x24201ca, order=0, oom_score_adj=0', 'typical'),
        (-2399, KERN, '{s} xcp01 kernel: Out of memory: Killed process 3321 (xapi) total-vm:2104576kB, anon-rss:1048576kB, file-rss:0kB', 'typical'),
        (-2300, DMN, '{s} xcp01 systemd[1]: xapi.service: main process exited, code=killed, status=9/KILL', 'typical')],
    cause="Per the read of the community health check: it lists dmesg lines containing \"out of memory\" as OOM events and flags dom0 memory use above 65%. That xapi was the victim here is this scenario's assumption.",
    resolution=['Check dom0 memory use and what grew (top, xe-toolstack-restart only after reading the kernel log), then consider more dom0 memory.', 'Restart the toolstack once memory is understood; running VMs are not touched by a toolstack restart.'],
    kbs=[kb(XS, XS_T, 'primary', '2026-10-13')], match=r'oom|Out of memory|xapi', notes=VN2)


tpl('CT-67', 'XCP-ng host: CIFS ISO mount stalls, hung tasks and disk I/O errors in the kernel log', 'xcpng', '8.x',
    'Host xcp01 becomes sluggish, the console hangs when browsing the ISO library and a local disk logs errors.',
    'mixed', ['xcp.mount_stall', 'xcp.io_error'], [
        (-2400, KERN, '{s} xcp01 kernel: CIFS: VFS: Server 192.0.2.70 has not responded in 180 seconds. Reconnecting...', 'typical'),
        (-2200, KERN, '{s} xcp01 kernel: INFO: task tapdisk:2210 blocked for more than 120 seconds.', 'typical'),
        (-2100, KERN, '{s} xcp01 kernel: blk_update_request: I/O error, dev sdb, sector 123456 op 0x0:(READ) flags 0x0 phys_seg 1 prio class 0', 'typical'),
        (-2090, SMLOG, '{s} xcp01 SM: [8812] Error: [Errno 5] Input/output error: /var/run/sr-mount/0a1b2c3d/6b5a4c3d.vhd', 'typical')],
    cause='Per the read of the community health check: it matches the CIFS message "has not responded in", the NFS "not responding" and the hung-task "blocked for more than", and its config comment warns the hung-task detector stops logging after a few warnings and can miss a long wedge. It also reports "Input/output error" in SMlog/xensource.log. Linking them to this symptom is the scenario\'s assumption.',
    resolution=['Probe each network mount with a stat and list processes in uninterruptible sleep (D state).', 'Check the file server and the disk behind the I/O errors (SMART, controller, array).'],
    kbs=[kb(XS, XS_T, 'primary', '2026-10-13')], match=r'has not responded|blocked for more than|I/O error|Input/output', notes=VN2)

tpl('CT-68', 'XCP-ng host: tapdisk crashes, the dom0 kernel then logs a panic / soft lockup', 'xcpng', '8.x',
    'A host rebooted by itself overnight and a VM disk process crashed shortly before.',
    'mixed', ['xcp.tapdisk_dead', 'xcp.kernel_fault'], [
        (-2400, SMLOG, '{s} xcp01 SM: [9021] Raising exception [46, The VDI is not available [opterr=TapdiskNotRunning: Tapdisk(vhd:/dev/VG_XenStorage-0a1b/VHD-6b5a) minor=2]]', 'typical'),
        (-2390, DMN, '{s} xcp01 systemd-coredump[5521]: Process 3321 (tapdisk) of user 0 dumped core.', 'typical'),
        (-1500, KERN, '{s} xcp01 kernel: watchdog: BUG: soft lockup - CPU#3 stuck for 23s! [kworker/3:1:221]', 'typical'),
        (-1490, KERN, '{s} xcp01 kernel: Kernel panic - not syncing: Fatal exception in interrupt', 'typical')],
    cause='Per the read of the community health check: its config says TapdiskNotRunning means tapdisk died and pairs with a core.tapdisk.* dump, and it flags dmesg "call trace" lines, /var/crash and systemd coredumps. That the crash preceded the panic here is the scenario\'s assumption.',
    resolution=['Keep the core dump and /var/crash files; check hardware (memory, storage controller) and the tapdisk/driver named in the trace.'],
    kbs=[kb(XS, XS_T, 'primary', '2026-10-13')], match=r'TapdiskNotRunning|tapdisk|soft lockup|Kernel panic|Call Trace', notes=VN2)

# ============================================================================= not templated (kept in the report only)
out = dict(version=1,
           source='SYNTHETIC scenarios CT-50..CT-%d built from public Vates / XCP-ng / Xen Orchestra web-search summaries (hostnames lab.example, addresses 192.0.2.x). '
                  'Log lines are approximations of real error names, not copied from real logs; they are not resolved support cases.' % (50 + len(T) - 1),
           templates=T)
path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'lvx', 'case_templates.json')
with open(path, 'w', encoding='utf-8', newline='\n') as f:
    json.dump(out, f, indent=1, ensure_ascii=False)
    f.write('\n')
print('wrote', os.path.normpath(path), len(T), 'templates;', sum(1 for t in T if t['bundle']), 'with bundles')
