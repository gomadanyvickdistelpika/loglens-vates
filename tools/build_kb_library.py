"""Regenerates lvx/kb_library.json.  The library is a SNAPSHOT of public Vates / XCP-ng / Xen Orchestra pages returned by web search
(title + URL + the date each was seen).  Only the search-result SUMMARIES were read, never the pages, so cause/resolution text is what a summary
stated and must be confirmed in the page; forum threads are community advice, not official guidance.  Edit the data below (or add entries through
LVX_KB_FILE) and re-run:   python tools/build_kb_library.py
Rules: never invent a URL, post number or version.  Only put in `resolution` what a summary actually stated; if only the title is known leave it empty."""
import json
import os

VATES_SEEN = '2026-10-10'     # date the pages below appeared in web-search results


def A(i, title):
    assert str(i).startswith('https://'), i
    return dict(id=str(i), title=title, seen=VATES_SEEN)


E = []


def kb(topic, rules, articles, cause='', resolution=(), match=None, notes='', basis='summary', priority=0):
    E.append(dict(topic=topic, priority=priority, rules=list(rules), match=match, articles=articles, cause=cause,
                  resolution=list(resolution), notes=notes, basis=basis))


# ----------------------------------------------------------------------------- Vates: XCP-ng / Xen Orchestra (public pages, search summaries only)
# Every article below was returned by a web search on VATES_SEEN (restricted to xcp-ng.org, docs.xcp-ng.org, xen-orchestra.com,
# docs.xen-orchestra.com, github.com and the Vates forums).  Only the search-result SUMMARY was read, never the page itself, so
# causes/resolutions are what the summary stated and must be confirmed in the page.  Forum threads are community advice, not official guidance.
F = 'https://xcp-ng.org/forum/topic/'
D = 'https://docs.xcp-ng.org/'
kb('Pool master (coordinator) unreachable / emergency mode', ['xcp.master_unreachable'],
   [A(D + 'troubleshooting/troubleshooting-ha/', 'High availability (HA) - XCP-ng troubleshooting docs'),
    A(F + '4075/pool-master-down-what-steps-need-done-next', 'Pool master down, what steps need done next?'),
    A(F + '10525/transfer-pool-master-only-partial-success', 'Transfer Pool Master / only partial success'),
    A(F + '8694/hosts-in-a-pool-have-gone-offline-after-reboot', 'Hosts in a pool have gone offline after reboot'),
    A(F + '9294/help-clean-shutdown-of-host-now-no-network-or-vms-are-detected', 'Help: Clean shutdown of Host, now no network or VMs are detected')],
   'Per the search summaries: a member cannot reach the pool coordinator; with HA enabled this can be tied to HA behaviour. Community advice: an emergency network reset on the affected host (after a toolstack restart on the master did not help) fixed one case.',
   ['Docs (summary): xe host-emergency-ha-disable force=true then xe-toolstack-restart to start from a stable state with HA off.',
    'If the master is really dead: xe pool-emergency-transition-to-master uuid=<host uuid> on a survivor, then xe pool-emergency-reset-master master-address=<new master> on the other hosts.',
    'Re-enable HA afterwards: xe pool-ha-enable heartbeat-sr-uuid=<sr uuid>.', 'A dead former master can be removed with xe host-forget uuid=<uuid> (forum answer). Vates guidance quoted in a thread: promote manually if you consider the host dead; HA can do it automatically but is tricky.'])
kb('HA: unexpected host reboot / self-fence', ['xcp.ha_fence'],
   [A(D + 'management/ha/', 'High availability - XCP-ng docs'), A(D + 'troubleshooting/troubleshooting-ha/', 'High availability (HA) - XCP-ng troubleshooting docs'),
    A('https://xcp-ng.org/blog/2024/08/22/xcp-ng-high-availability-a-guide/', 'XCP-ng High Availability: a guide'),
    A(F + '12483/ha-causes-reboot-of-xcp-ng-nodes', 'HA causes reboot of xcp-ng nodes'),
    A(F + '9436/other-2-hosts-reboot-when-1-host-in-ha-enabled-pool-is-powered-off', 'Other 2 hosts reboot when 1 host in HA enabled pool is powered off'),
    A(F + '9161/can-t-enable-high-availability-feature', "Can't Enable High Availability Feature")],
   'Per the docs summary: a host that loses both network and storage heartbeat treats itself as problematic and does a hard power-off/restart (default timeout 60 s). Heartbeats are UDP over the management network and a ha-statefile on the heartbeat SR. At least 3 hosts are recommended; with two, loss of the link between them can get hosts fenced.',
   ['Check /var/log/xha.log to see whether the host self-fenced or another host requested the reboot.', 'A fenced host that cannot reach the heartbeat disk reports it could not join the liveset (docs summary).',
    'One forum report attributes repeated reboots to heartbeat packets routed out of the wrong bonded interface (community analysis, not official).', 'To investigate stability: xe host-emergency-ha-disable force=true and xe-toolstack-restart (docs summary).'])
kb('Control domain / log partition full', ['xcp.host_disk_full'],
   [A(F + '3028/logs-partition-full', 'Logs Partition Full'), A(F + '11630/log_fs_usage-var-log-directory-on-pool-master-filling-up-constantly/13', 'log_fs_usage / /var/log directory on pool master filling up constantly'),
    A(F + '3597/disk-usage-for-control-domain-on-server-abc-mydomain-com-has-reached-92', "Disk Usage for Control Domain on server 'abc.mydomain.com' has reached 92%."),
    A(F + '7246/xen-orchestra-update-failed-error-enospc-no-space-left-on-device', 'Xen Orchestra Update Failed - Error: ENOSPC: no space left on device')],
   'Per the summaries: /var/log is a small separate partition and / can fill for reasons other than logs. In one pool-master case SR.scan log spam filled /var/log.',
   ['Find the big files first: du -xh /var/log | sort -h | tail, and df -h.', 'Pool-master case: lower SR rescan frequency with xe host-param-set other-config:auto-scan-interval=120 uuid=<host uuid>; old XenTools were also suspected in the thread.',
    'One thread traced a full /var/log to XS80E* hotfix entries that should not exist on XCP-ng (a Vates engineer suspected a buggy XCP-Center offering Citrix hotfixes).'])
kb('xapi / toolstack not responding or not coming back', ['xcp.xapi_down'],
   [A(D + 'troubleshooting/common-problems/', 'Common Problems - XCP-ng docs'), A(F + '4734/toolstack-reboot-and-100-disk-usage-bad-idea', 'toolstack-reboot and 100% disk usage. Bad idea'),
    A(F + '8721/xe-sr-list-error-connection-refused-calling-connect', 'xe sr-list Error: Connection refused (calling connect )'), A(F + '10737/master-xcp-host-stuck-urgent', 'Master XCP host stuck - Urgent')],
   'Per the summaries: the toolstack restart only affects management services (running VMs untouched) but removes backup/export tasks. A full log partition, a database inconsistency or (in one thread) a certificate entry whose file was deleted can keep xapi from starting.',
   ['Check xe task-list before restarting; check service xapi status and /var/log/daemon.log.', 'Free disk space; if it still fails a host reboot was the usual last resort in the threads.',
    'Stale certificate case: the poster downgraded xapi, recreated a dummy certificate file so xe pool-certificate-uninstall could remove the DB entry, then upgraded again (single forum report).'])
kb('Rolling Pool Update / yum update failures', ['xcp.update_fail'],
   [A(D + 'management/updates/', 'Updates - XCP-ng docs'), A(F + '9501/rolling-pool-update-failed', 'Rolling Pool Update Failed'), A(F + '8940/rolling-pool-update-failing', 'Rolling Pool Update - failing'),
    A(F + '10901/rolling-pool-update-not-possible-to-resume-a-failed-rpu', 'Rolling Pool Update - not possible to resume a failed RPU'),
    A(F + '12136/rpu-failure-on-8.3-yum-https-500-error-for-xo-lite-package-hung-task', 'RPU Failure on 8.3: Yum HTTPS 500 Error for xo-lite package (Hung Task)'),
    A(F + '9491/yum-update-no-more-free-space', 'yum update, no more free space?')],
   'Per the summaries: causes reported include incomplete yum transactions, stale repo metadata, repository mirror HTTP 500 errors, a full root filesystem, scheduled backups/replication running during the RPU, and CANNOT_EVACUATE_HOST when a VM booted on CPU features the target host lacks.',
   ['Clean up incomplete yum transactions / run yum clean all, then update again.', 'Disable backups during the RPU (community ambassador advice in a thread).', 'CANNOT_EVACUATE_HOST for CPU features: shut the VM down and boot it again (Vates co-founder suggestion in a thread).',
    'Manual fallback from forum staff: yum update with the xcp-ng-base and xcp-ng-updates repos on each host, migrating VMs away before rebooting each host.'],
   notes='After a failed RPU the pool may report no missing patches on the master while other hosts still need them (forum report).')
kb('SR full: coalesce cannot run, snapshots fail', ['xcp.sr_full'],
   [A('https://xen-orchestra.com/docs/backup_troubleshooting.html', 'Backup troubleshooting - Xen Orchestra docs'), A(F + '10489/issue-with-sr-and-coalesce/21?page=1', 'Issue with SR and coalesce'),
    A(F + '11226/some-backups-failing', 'Some backups failing'), A(F + '1290/base-copy-vdi-not-merged', 'Base Copy / VDI not merged'), A(F + '6887/how-to-recover-free-space-after-delete-snapshots/2', 'How to recover free space after delete snapshots')],
   'Per the summaries: coalesce runs after a snapshot is deleted and can fail when the SR lacks free space, which then keeps the SR full; the XO docs suggest keeping 30% or more free. A snapshot on thick-provisioned LVM reserves the full disk size. One forum case shows SR_BACKEND_FAILURE_44 (insufficient space) caused by a separate, nearly full SR.',
   ['Free space first: move VMs/disks to another SR (also forces a coalesce) or delete old snapshots keeping the base and the latest.', 'Rescan the SR to restart coalesce (harmless, not guaranteed).', 'Shut the VMs down before rescanning for a better chance of offline coalesce (user report).',
    'Vates staff (forum) recommend thin-provisioned storage such as local ext over thick LVM for large disks.'])
kb('Coalesce / garbage collection stuck', ['xcp.coalesce_stuck'],
   [A(F + '10271/sr-garbage-collection-running-permanently', 'SR Garbage Collection running permanently'), A(F + '9569/vdi-to-coalesce-495', 'VDI to coalesce (495)'), A(F + '5784/snapshot-chain-too-long-in-nfs-sr', 'Snapshot chain too long in NFS SR'),
    A(F + '1290/base-copy-vdi-not-merged', 'Base Copy / VDI not merged'), A('https://xen-orchestra.com/docs/backup_troubleshooting.html', 'Backup troubleshooting - Xen Orchestra docs')],
   'Per the summaries: a VDI to coalesce count that does not fall means coalesce is stuck; repeated UNDO LEAF-COALESCE entries appear in SMlog in one thread; a Vates engineer said the garbage collector cannot run when it cannot edit a corrupted VDI.',
   ['grep for exceptions and coalesce in /var/log/SMlog on the relevant host; ps axf | grep vhd to see a running coalesce.', 'Rescan the SR to trigger a coalesce.', 'Migrating the VM disks to another SR forces a coalesce (last resort per XO docs).',
    'A 8.3 leaf-coalesce timeout workaround edits LIVE_LEAF_COALESCE_MAX_SIZE / LIVE_LEAF_COALESCE_TIMEOUT in /opt/xensource/sm/cleanup.py - unofficial forum advice, back up first.', 'Removing a confirmed-orphaned parent VHD by hand worked once (cleanup then took about 20 h on NFS) - risky, forum report only.'])
kb('VDI chain too long (SR_BACKEND_FAILURE_109)', ['xcp.sr_chain'],
   [A(F + '4177/error-sr_backend_failure_109-the-snapshot-chain-is-too-long', 'Error: SR_BACKEND_FAILURE_109(, The snapshot chain is too long, )'), A(F + '5887/unhealthy-vdi-chain', 'unhealthy VDI chain'),
    A(F + '10855/vdi-chain-on-deltas', 'VDI Chain on Deltas'), A(F + '1840/delta-backup-fails-for-specific-vm-with-vdi-chain-error', 'Delta backup fails for specific vm with VDI chain error'),
    A(F + '2471/xoa-backups-skipped-to-protect-vdi-chain/23', 'XOA - backups skipped to protect VDI chain'), A('https://xen-orchestra.com/docs/backup_troubleshooting.html', 'Backup troubleshooting - Xen Orchestra docs')],
   'Per the XO docs summary: XCP-ng caps a VHD chain at 30 elements and the error is a protection mechanism; the system should coalesce the chain automatically, so a stuck coalesce is the usual cause.',
   ['Look at the SR Advanced tab in XO for the VDI to coalesce count and at /var/log/SMlog on the host.', 'Rescan the SR; migrate the disks to another SR as a last resort.'])
kb('SR / PBD not plugged after reboot (iSCSI, NFS, local)', ['xcp.sr_unplugged'],
   [A(F + '10903/how-to-re-attach-an-sr', 'How to Re-attach an SR'), A(F + '5981/unstable-nfs-sr-mounts', 'Unstable NFS SR mounts'), A('https://github.com/xcp-ng/xcp/issues/260', 'After upgrade to 8.0: iSCSI connection fails after reboot · Issue #260 · xcp-ng/xcp'),
    A(F + '7562/host-chronically-losing-local-sr', 'Host chronically losing local SR'), A(F + '8893/unable-to-unmount-iscsi-sr-sr_backend_failure_1200', 'Unable to unmount iscsi SR - SR_BACKEND_FAILURE_1200')],
   'Per the summaries: causes in different threads were an iSCSI login/discovery problem (CHAP), a missing /dev/disk/by-scsid device, stale NFS mounts, and corrupted LVM metadata on a local drive. No single fix applies.',
   ['Check xensource.log and SMlog while running xe pbd-plug.', 'iSCSI: run iscsiadm sendtargets discovery first, check whether iscsid is hung.', 'NFS: unmount the stale path, reconnect; consider hard (or hard,vers=4) mount options.', 'NFS server as a VM on the same host: autostart that VM first, then xe pbd-plug (user script).'])
kb('Not enough free memory to start / migrate / evacuate', ['xcp.vm_no_memory'],
   [A(F + '3991/not-enough-server-memory-when-start-vm', 'Not enough server memory when start VM'), A(F + '9929/xcp-ng-host-ram', 'xcp-ng host RAM'),
    A('https://github.com/xapi-project/xen-api/issues/4323', 'Mysterious failure in HA with HOST_NOT_ENOUGH_FREE_MEMORY · Issue #4323 · xapi-project/xen-api'), A(F + '11688/unable-to-migrate-vdi-when-host-is-low-on-free-memory', 'Unable to MIgrate VDI when host is low on free memory'),
    A(F + '4430/xcp-ng-8-2-rolling-update-error', 'XCP-ng 8.2 Rolling Update Error')],
   'Per the summaries: memory already committed (dynamic-max of all VMs plus dom0), stale state after migrations, and, with HA enabled, evacuation failing with HOST_NOT_ENOUGH_FREE_MEMORY even when memory is free (GitHub issue; advice in a thread: disable HA before a rolling pool update).',
   ['Compare xe host-list params=memory-free with xe vm-compute-maximum-memory for the VM.', 'Restart the toolstack or reboot the host; switch the VM to static memory.', 'Disable HA before a rolling pool update.'])
kb('VM fails to start (bootloader, emulator, power state)', ['xcp.vm_start_fail'],
   [A(F + '5664/failed-to-start-vm', 'Failed to start VM'), A(F + '10474/error-no-kernel-found', 'error no kernel found'), A(F + '5706/the-emulator-required-to-run-this-vm-failed-to-start', 'The emulator required to run this VM failed to start..?'),
    A(F + '9026/vm_bad_power_state', 'VM_BAD_POWER_STATE'), A(F + '5637/vm-hang-can-t-restart-can-t-power-on', "VM Hang - Can't restart, can't power on."), A(F + '5112/xcp-host-rebooted-vm-s-wont-start-anymore', "XCP host rebooted: VM's wont start anymore :-(")],
   'Per the summaries: PV-mode guests with a changed bootloader fail with "no kernel/loader found" (PV is no longer supported; convert to HVM and install GRUB); FAILED_TO_START_EMULATOR after a patch update; attached CD/ISO images; missing Secure Boot certificates; a VM on local storage of another host; a full disk. No search result matched HVM_BOOT_FAILED or VM_FAILED_SHUTDOWN_ACKNOWLEDGMENT specifically.',
   ['Read /var/log/xensource.log (and xl dmesg) for the first underlying error.', 'Restart the toolstack on all hosts or reboot them; try another host.', 'xe vm-cd-eject --multiple if a stale ISO is attached.',
    'xe vm-reset-powerstate (--force) only when the old host is truly down (XAPI refuses while the host is live); a dead master may first need xe pool-emergency-transition-to-master and xe pool-recover-slaves (thread reports).'])
kb('Live migration / storage migration failures', ['xcp.migrate_fail'],
   [A(F + '9801/live-migration-fails-mirror_failed', 'Live Migration Fails: MIRROR_FAILED'), A(F + '4416/migrate-failed', 'Migrate failed'), A(F + '8196/live-migrate-between-two-stand-alone-pools-fails', 'Live Migrate between two stand alone pools fails'),
    A(F + '3771/vm-migration-failed-now-can-t-access-vm', "VM Migration Failed & Now Can't Access VM"), A(F + '6496/vm-migrate-problem', 'VM Migrate problem')],
   'Per the summaries: a live storage migration fails (MIRROR_FAILED) when the VM writes faster than the block mirror can copy; other causes were a dynamic minimum memory that is too low, no free memory on the target, MCS VMs not supporting storage XenMotion, and a bad power state.',
   ['Check /var/log/xensource.log on the source host.', 'Large write-heavy VMs: warm migration (Vates CEO suggestion in a thread).', 'A VM left looking running after a failed migration: xe vm-reset-powerstate or a toolstack restart (threads).'])
kb('XO backup: VDI_IO_ERROR and remote problems', ['xcp.xo_backup'],
   [A('https://xen-orchestra.com/docs/backup_troubleshooting.html', 'Backup troubleshooting - Xen Orchestra docs'), A('https://github.com/vatesfr/xen-orchestra/issues/3242', '[Backup Ng deltaBackup] VDI_IO_ERROR(Device I/O errors) · Issue #3242 · vatesfr/xen-orchestra'),
    A('https://github.com/vatesfr/xen-orchestra/issues/5451', 'Backup job failed / Remotes issue · Issue #5451 · vatesfr/xen-orchestra'), A(F + '2991/vdi_io_error-device-i-o-errors-when-you-run-scheduled-backup/55', 'VDI_IO_ERROR(Device I/O errors) when you run scheduled backup')],
   'Per the XO docs summary: VDI_IO_ERROR comes from the host (dom0), not XO: the host could not read the VM disk during the HTTP export. Listed causes: a corrupted VDI or a race during snapshots, a too-slow SR, a long job timeout with a slow remote. For NFS remotes a forum thread suggests a hard mount or adjusted soft timeout/retries.',
   ['grep -i error /var/log/SMlog on the host for coalesce or VDI corruption.', 'Check the job timeout, overlap with other jobs, and the NFS mount options on the XO host/remote.'])
kb('XO cannot connect to a pool: self-signed / expired certificate', ['xcp.xo_tls'],
   [A('https://xen-orchestra.com/blog/improving-security-in-xen-orchestra/', 'Improving security in Xen Orchestra'), A('https://xen-orchestra.com/docs/troubleshooting.html', 'Troubleshooting - Xen Orchestra docs'),
    A('https://github.com/vatesfr/xen-orchestra/issues/2723', 'SSL certificate verification fails in stats query · Issue #2723 · vatesfr/xen-orchestra')],
   'Per the summaries: since a 5.8.x release XO does not connect to a host with an invalid (self-signed or expired) certificate unless that is explicitly allowed in the UI; plain HTTP is possible but unencrypted; the docs describe regenerating an expired appliance certificate with openssl and restarting xo-server.',
   ['Accept the certificate via the warning/toggle in the server settings after verifying it, or install a trusted certificate on every pool host (xe commands exist for host certificates).', 'Expired appliance cert: back up /etc/ssl cert.pem/key.pem, regenerate with openssl req -x509, restart xo-server (docs summary).'])
kb('XO appliance / backup remote out of space (ENOSPC)', ['xcp.xo_disk_full'],
   [A(F + '7246/xen-orchestra-update-failed-error-enospc-no-space-left-on-device', 'Xen Orchestra Update Failed - Error: ENOSPC: no space left on device'), A(F + '5788/backup-error-with-space-available', 'Backup error with space available')],
   'Per the search-result titles only: an XO update failed with ENOSPC, and another thread covers a backup error although space seemed available. The article text was not read, so no cause is claimed here.',
   [], basis='title')
kb('XO from sources: build / node errors', ['xcp.xo_build'],
   [A('https://docs.xen-orchestra.com/getting-started/install-from-sources', 'Installing XO from source'), A('https://github.com/vatesfr/xen-orchestra/issues/2774', 'Errors during build process · Issue #2774 · vatesfr/xen-orchestra'),
    A('https://github.com/vatesfr/xen-orchestra/issues/5782', 'loader.js - Cannot find module · Issue #5782 · vatesfr/xen-orchestra'), A('https://github.com/ronivay/XenOrchestraInstallerUpdater/issues/62', 'Build fails with error · Issue #62 · ronivay/XenOrchestraInstallerUpdater')],
   'Per the summaries: a node version that does not satisfy the engine requirement, native module compile errors on unsupported node versions, or a regression in a specific commit.',
   ['Clean rebuild per the docs: remove node_modules, run yarn, then yarn build.', 'Check the node version against the engine requirement in the error.'])
kb('XOA / XO update failures', ['xcp.xoa_update'],
   [A('https://docs.xen-orchestra.com/getting-started/troubleshooting', 'Troubleshooting - Xen Orchestra docs'), A('https://xen-orchestra.com/docs/updater.html', 'Updates - Xen Orchestra docs'), A('https://xen-orchestra.com/forum/topic/50/update-error', 'Update error - Xen Orchestra forum')],
   'Per the summaries: transparent proxies breaking the updater with SSL/TLS errors, a corrupted or missing package, missing network access to xen-orchestra.com and nodejs.org on 443, or a missing registration.',
   ['xoa check, then journalctl -u xoa-updater -f -n 50 while reproducing.', 'Delete /var/lib/xoa-updater/update.json and run xoa-updater --upgrade to force a fresh download.', 'Proxy workaround from the docs summary (lowers TLS security): NODE_TLS_REJECT_UNAUTHORIZED=0 in /etc/xo-appliance/env, restart xoa-updater.'])

lib = dict(researched=VATES_SEEN,
           source='Titles and URLs of public Vates / XCP-ng / Xen Orchestra pages returned by web search on %s; only the search-result summaries were used, the pages themselves were not read.' % VATES_SEEN,
           entries=E)
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'lvx', 'kb_library.json')
with open(out, 'w', encoding='utf-8', newline='\n') as f:
    json.dump(lib, f, indent=1, ensure_ascii=False)
    f.write('\n')
print('wrote', os.path.normpath(out), len(E), 'entries')
