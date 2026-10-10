"""Signature rules for Vates products: XCP-ng hosts / pools and Xen Orchestra (XO).
`kw` is a lowercase literal prefilter (cheap) run before the regex: every rule needs a `kw`, and every regex alternative must contain one of its
keywords ('|' = any-of).  Patterns come from error names and phrases seen in PUBLIC XCP-ng / Xen Orchestra docs, forum and GitHub search summaries
(see tools/build_kb_library.py); they are generic triage signatures, not verified against real customer logs.  Triage aid, not a root-cause verdict."""
import re

R = []


def rule(id, title, product, severity, topics, kw, pattern, advice, kb=None, search=None, files=None, symptom=False, root_for=()):
    """symptom=True marks a downstream effect or locator ('chain too long', 'VM failed to start'): ranked just below an earlier, likelier cause.
    root_for lists rule ids this finding is an early warning of: if one of them follows later, this ranks above it."""
    R.append(dict(id=id, title=title, product=product, severity=severity, topics=topics,
                  kw=kw.lower(), rx=re.compile(pattern, re.I), advice=advice, kb=kb,
                  search=search or title, files=re.compile(files, re.I) if files else None, symptom=symptom, root_for=tuple(root_for)))


# ---------------- Vates: XCP-ng hosts / pools and Xen Orchestra (XO) ----------------
# Patterns come from error names and phrases seen in PUBLIC XCP-ng / Xen Orchestra docs, forum and GitHub search summaries
# (see tools/build_kb_library.py). They are generic triage signatures, not verified against real customer logs.
rule('xcp.host_disk_full', 'XCP-ng host: dom0 / or /var/log partition full', 'xcpng', 'high', ['disk-space', 'services'],
     'no space left|enospc|control domain|log_fs_usage|/var/log',
     r'No space left on device|ENOSPC|Disk Usage for Control Domain.{0,80}reached \d+%|log_fs_usage|/var/log.{0,40}(?:100%|\bfull\b)',
     'The control domain (dom0) filesystem is full. Run df -h and du -xh /var/log | sort -h | tail; a full / or /var/log stops xapi, yum and logging, and the toolstack may need a host reboot after space is freed. Check for log spam (frequent SR scans, old guest tools) and lower SR auto-scan frequency if it is the source.',
     search='XCP-ng /var/log full dom0 disk usage control domain', root_for=('xcp.xapi_down', 'xcp.update_fail'),
     files=r'^(?!.*(?:xo-server|xo-web|xo-proxy|xoa|xo/|xo_server|journalctl|xo-install|xen-?orchestra)).*$')
rule('xcp.xapi_down', 'XCP-ng host: xapi / toolstack not responding or restart loop', 'xcpng', 'high', ['services', 'host-connection'],
     'xapi|toolstack|calling connect',
     r'xapi\.service.{0,60}(?:exited|failed|died)|\bxapi (?:daemon |service )?(?:has |is )?(?:died|exited|not running|crashed|stopped unexpectedly|failed to start)|xapi\.service.{0,40}(?:holdoff|scheduling restart|start request repeated too quickly)|xe-toolstack-restart|toolstack.{0,40}(?:restart|not respond|fail)|Connection refused \(calling connect|Unable to connect to xapi|xapi (?:is )?restart(?:ing)? in a loop',
     'The management toolstack (xapi) is down or flapping, so xe commands and Xen Orchestra cannot talk to the host. Check service xapi status, /var/log/daemon.log and xensource.log, free disk space and the certificate/database state; xe-toolstack-restart does not touch running VMs but removes active tasks (check xe task-list first).',
     search='XCP-ng xapi not responding toolstack restart connection refused', symptom=True)
rule('xcp.update_fail', 'XCP-ng update / Rolling Pool Update failure (yum, evacuation)', 'xcpng', 'high', ['upgrade', 'services'],
     'yum|rolling pool|rpu|cannot_evacuate|repository metadata|http error|transaction|mirrorlist|downloading packages',
     r'yum.{0,80}(?:error|fail|cannot|timed out)|Rolling Pool Update.{0,80}(?:fail|abort|error|stuck)|\bRPU\b.{0,60}(?:fail|abort|hung)|CANNOT_EVACUATE_HOST|Cannot retrieve repository metadata|HTTP Error 5\d\d|Transaction check error|incomplete transactions?|Could not retrieve mirrorlist|Error downloading packages',
     'A host update or Rolling Pool Update stopped. Typical causes in public reports: full root filesystem, stale/incomplete yum transactions (yum clean all), repository mirror errors (HTTP 5xx), scheduled backups running during the RPU, and evacuation blocked by HA or CPU-feature mismatch (HOST_NOT_ENOUGH_FREE_MEMORY / CANNOT_EVACUATE_HOST). Read the first error in the RPU task and in yum output, not the last.',
     search='XCP-ng rolling pool update failed yum CANNOT_EVACUATE_HOST')
rule('xcp.master_unreachable', 'XCP-ng pool: coordinator (master) unreachable / emergency mode', 'xcpng', 'critical', ['host-connection', 'ha', 'services'],
     'master|coordinator|emergency|host_is_slave',
     r'pool master (?:is )?(?:unreachable|not reachable|down|cannot be contacted)|(?:cannot|unable to|could not) (?:contact|connect to|reach) (?:the )?(?:pool )?(?:master|coordinator)|HOST_IS_SLAVE|(?:pool-)?emergency[- ]?(?:mode|transition|reset)|Lost (?:contact|connection) (?:with|to) (?:the )?(?:pool )?(?:master|coordinator)|host-emergency-ha-disable',
     'A member host cannot reach the pool coordinator (master) and may be in emergency mode. First establish whether the master is alive: network/bond on the management interface, xapi on the master, HA state. Only if the master is really dead, promote a surviving host (xe pool-emergency-transition-to-master, then pool-emergency-reset-master on the others). Disable HA first if it is enabled.',
     search='XCP-ng pool master unreachable emergency mode pool-emergency-transition-to-master', root_for=('xcp.xapi_down',))
rule('xcp.ha_fence', 'XCP-ng HA: host self-fenced / heartbeat or statefile lost', 'xcpng', 'critical', ['ha', 'network', 'storage'],
     'xha|fenc|liveset|heartbeat|statefile',
     r'xha.{0,100}(?:fenc|self-fenc|reboot|timed out|lost|failed)|self[- ]?fenc\w*|(?:could not|unable to|cannot) join (?:the )?liveset|(?:HA|xha) daemon.{0,60}(?:access|reach).{0,30}heartbeat disk|heartbeat disk|statefile.{0,60}(?:fail|unreach|lost|timeout|timed out)|(?:host|node) .{0,30}(?:was )?fenced|HA_HOST_CANNOT_ACCESS_STATEFILE|(?:cannot|unable to|could not|lost access to|failed to) (?:access |open |read |write )?(?:the )?(?:ha-)?statefile',
     'A host rebooted because XCP-ng HA could not see the network heartbeat and/or the storage heartbeat (ha-statefile) within the HA timeout, so it fenced itself. Read /var/log/xha.log to see whether it self-fenced or another host asked it to. Check the management network/bond path and the heartbeat SR on all hosts; HA is fragile with fewer than three hosts.',
     search='XCP-ng HA host reboot self-fence xha.log heartbeat statefile', root_for=('xcp.master_unreachable', 'xcp.vm_start_fail'))
rule('xcp.sr_full', 'XCP-ng storage: SR full / insufficient space', 'xcpng', 'critical', ['storage', 'disk-space'],
     'sr|storage repository|insufficient|not enough|lvm',
     r'(?:\bSR\b|storage repository).{0,60}(?:\bfull\b|out of space|over-?committed|no (?:more )?free space)|Insufficient (?:free )?space|SR_BACKEND_FAILURE_44|not enough (?:free )?space (?:on|in) (?:the )?SR|LVM.{0,40}insufficient free space|Volume group .{0,80}insufficient free space',
     'A storage repository has no room. Coalesce (which frees snapshot space) and new snapshots both need free space, so a full SR also causes stuck coalesce, long VDI chains, failed backups and VMs that cannot start. Free space (move VMs/disks to another SR, delete old snapshots) before anything else; public guidance suggests keeping roughly 30% free, especially on thick-provisioned LVM SRs.',
     search='XCP-ng SR full insufficient space SR_BACKEND_FAILURE_44 coalesce',
     root_for=('xcp.coalesce_stuck', 'xcp.sr_chain', 'xcp.vm_start_fail', 'xcp.xo_backup'))
rule('xcp.coalesce_stuck', 'XCP-ng storage: coalesce / garbage collection failing or stuck', 'xcpng', 'high', ['storage', 'backup', 'performance'],
     'smgc|coalesce|garbage collect',
     r'SMGC.{0,120}(?:exception|failed|abort|timed? ?out|giving up|Unable to|UNDO LEAF-COALESCE|stuck)|UNDO LEAF-COALESCE|leaf-?coalesce.{0,60}(?:fail|timed? ?out|abort|too (?:big|large))|Coalesce.{0,40}(?:failed|exception|aborted)|garbage collect\w*.{0,60}(?:fail|stuck|exception|abort)|no space.{0,40}coalesce|coalesce.{0,40}no space|SMGC.{0,60}\berror|SMGC.{0,120}completed with errors',
     'The storage manager cannot merge (coalesce) VHD snapshots. Look at /var/log/SMlog for SMGC exceptions or repeated UNDO LEAF-COALESCE, check SR free space first, a corrupted VDI, stale mounts, and whether a vhd coalesce process is running; a rescan restarts the garbage collector. A stuck coalesce is the usual cause of a too-long VDI chain.',
     search='XCP-ng SMlog coalesce stuck garbage collector UNDO LEAF-COALESCE', root_for=('xcp.sr_chain', 'xcp.xo_backup'))
rule('xcp.sr_chain', 'XCP-ng storage: VDI snapshot chain too long (SR_BACKEND_FAILURE_109)', 'xcpng', 'high', ['storage', 'backup'],
     'sr_backend_failure_109|chain|too many',
     r'SR_BACKEND_FAILURE_109|snapshot chain is too long|VDI chain.{0,40}(?:too long|unhealthy|too many)|unhealthy VDI chain|skipped to protect VDI chain|too many (?:VHD|snapshots|vdis)',
     'The VHD chain reached its limit (30 elements) because coalesce is not keeping up. This is a protection, not the cause: find why coalesce is stuck (SR space, corrupted VDI, slow SR, stale snapshots from backups) and fix that. Migrating the VM disks to another SR forces a coalesce as a last resort.',
     search='XCP-ng SR_BACKEND_FAILURE_109 snapshot chain is too long coalesce', symptom=True)
rule('xcp.sr_unplugged', 'XCP-ng storage: SR / PBD not plugged (iSCSI / NFS / local) after reboot or outage', 'xcpng', 'high', ['storage', 'network'],
     'pbd|not available|by-scsid|iscsi|nfs|stale file handle',
     r'PBD_PLUG_FAILED|pbd[-. _]?plug.{0,60}(?:fail|error)|(?:SR|device) .{0,60}(?:is )?not available|by-scsid/\S+.{0,40}(?:does not exist|not found|No such)|iscsiadm.{0,80}(?:fail|error|login|timed out)|iscsid.{0,160}(?:login failed|hung|timed out|fail)|mount\.nfs.{0,80}(?:timed out|fail|stale|denied|unreachable)|Stale file handle|nfs: server \S+ not responding',
     'The host could not attach (plug) the SR. Check on the host: the iSCSI session (iscsiadm -m session, CHAP, discovery), whether the /dev/disk/by-scsid device exists, the NFS server/export and stale mounts (consider hard mounts), and for a local SR the LVM/ZFS pool state; then retry xe pbd-plug. Read SMlog while plugging.',
     search='XCP-ng SR not available PBD plug failed after reboot iSCSI NFS')
rule('xcp.vm_no_memory', 'XCP-ng VM: not enough free host memory (start / migrate / evacuate)', 'xcpng', 'high', ['memory', 'vm'],
     'memory',
     r'HOST_NOT_ENOUGH_FREE_MEMORY|not enough (?:server |free |host )?memory|(?:not|n.t) have enough (?:free )?memory|(?:xenguest|domain_create).{0,60}out of memory|Cannot allocate memory.{0,60}(?:domain|xc_|xenguest)|(?:xenguest|xc_domain|domain)\w*.{0,60}Cannot allocate memory',
     'The host cannot give the VM its memory. Compare xe host-list params=memory-free with the VM requirement, remember dom0 memory and the dynamic-max of all running VMs, consider static memory, restart the toolstack or move VMs. During evacuation with HA enabled this error can appear even with free memory: disable HA before a rolling update.',
     search='XCP-ng HOST_NOT_ENOUGH_FREE_MEMORY VM will not start', root_for=('xcp.vm_start_fail', 'xcp.migrate_fail', 'xcp.update_fail'))
rule('xcp.vm_start_fail', 'XCP-ng VM: failed to start (boot / emulator / power state)', 'xcpng', 'high', ['vm'],
     'hvm|bootloader|shutdown_acknowledgment|failed to|unable to|xenguest|domain_create|bad_power_state|emulator',
     r'HVM[_ ]BOOT[_ ]FAILED|VM_FAILED_SHUTDOWN_ACKNOWLEDGMENT|BOOTLOADER_FAILED|VM_BAD_POWER_STATE|FAILED_TO_START_EMULATOR|emulator.{0,60}failed to start|(?:Failed|Unable) to (?:start|create|build) (?:the )?(?:VM|domain|guest)|xenguest.{0,60}(?:fail|error)|domain_create.{0,40}fail',
     'The VM did not come up. Read xensource.log around the start for the first underlying error (memory, SR/VDI, emulator, bootloader/kernel, power state). Public reports: restart the toolstack, start on another host, eject stale CD/ISO, check the SR is plugged, and use xe vm-reset-powerstate only when the old host is truly down.',
     search='XCP-ng VM fails to start HVM boot failed emulator bootloader', symptom=True)
rule('xcp.migrate_fail', 'XCP-ng VM: live migration / storage migration failed', 'xcpng', 'high', ['vm', 'storage', 'network'],
     'migrat|mirror_failed|xenmotion',
     r'MIRROR_FAILED|VM_MIGRATE_FAILED|migrat\w*.{0,60}(?:fail|abort|timed out|error)|(?:Storage )?XenMotion.{0,40}fail',
     'Migration failed. Read xensource.log on the SOURCE host for the underlying error. Common public causes: block mirror cannot keep up with a write-heavy VM (MIRROR_FAILED; consider warm migration), dynamic memory minimum too low or no free memory on the target, CPU feature mismatch, MCS/unsupported storage motion, and a VM left in a wrong power state afterwards.',
     search='XCP-ng live migration failed MIRROR_FAILED VM_MIGRATE_FAILED xensource.log')
rule('xcp.xo_backup', 'Xen Orchestra backup / replication job failed (VDI_IO_ERROR, snapshot, remote)', 'xo', 'high', ['backup', 'storage'],
     'vdi_io_error|backup|replication|delta|unhealthy vdi|remote',
     r'VDI_IO_ERROR|(?:backup|replication|delta).{0,60}(?:job )?(?:failed|interrupted|aborted|timed out)|backup.{0,40}skipped|unhealthy VDI chain|(?:Backup|job) .{0,40}(?:ENOSPC|no space left)|remote .{0,60}(?:unreachable|not mounted|disconnected|ESTALE|EIO)',
     'An XO backup/replication run failed. VDI_IO_ERROR comes from the host (dom0 could not read the disk during export), not from XO: check the host SMlog for corrupted VDIs, coalesce backlog and SR speed. Also check the remote (NFS hard mount, free space, timeouts), jobs overlapping each other, and a skipped run protecting a long VDI chain.',
     search='Xen Orchestra backup failed VDI_IO_ERROR delta backup NFS remote', symptom=True)
rule('xcp.xo_tls', 'Xen Orchestra: TLS / self-signed or expired certificate when connecting to a pool or host', 'xo', 'high', ['certificate', 'host-connection', 'services'],
     'self_signed|depth_zero|unable_to_verify|verify the first certificate|cert_has_expired|altname|self signed|self-signed|websocket|certificate has expired',
     r'SELF_SIGNED_CERT_IN_CHAIN|DEPTH_ZERO_SELF_SIGNED_CERT|UNABLE_TO_VERIFY_LEAF_SIGNATURE|CERT_HAS_EXPIRED|ERR_TLS_CERT_ALTNAME_INVALID|self[- ]signed certificate|unable to verify the first certificate|(?:server|connection to|xapi).{0,60}(?:websocket|ws)\b.{0,40}(?:fail|closed|error)|certificate has expired',
     'XO refuses (or the browser silently fails) to talk to a host/pool or to the appliance because the certificate is self-signed, expired or does not match the name. In XO either accept the certificate via the server settings (allow unauthorized) after verifying it, install a certificate you trust on the hosts (every host in the pool), or regenerate the expired appliance certificate and restart xo-server.',
     search='Xen Orchestra cannot connect to pool self-signed certificate SELF_SIGNED_CERT_IN_CHAIN')
rule('xcp.xo_build', 'Xen Orchestra from sources: build / node / yarn failure', 'xo', 'high', ['upgrade', 'services'],
     'engine "node"|gyp|cannot find module|yarn|command failed with exit code|leveldown|node_modules|npm err',
     r'The engine "node" is incompatible|node-gyp|gyp ERR|Cannot find module|yarn(?: build)?.{0,40}(?:error|failed)|error Command failed with exit code|leveldown|EACCES.{0,40}node_modules|npm ERR!',
     'The XO source build or start failed. Check the node version against the engine requirement in the error, then do a clean rebuild (remove node_modules, yarn, yarn build); native module compile errors (leveldown / node-gyp) usually mean an unsupported node version; if a fresh commit broke the build, try a known-good commit or the XOA.',
     search='Xen Orchestra from sources yarn build engine node incompatible Cannot find module')
rule('xcp.xoa_update', 'XOA / XO updater failure (xoa-updater, proxy TLS, registration, network)', 'xo', 'high', ['upgrade', 'services', 'network'],
     'xoa-updater|update.json|xen-orchestra.com|nodejs.org|node_tls|not registered',
     r'xoa-updater.{0,100}(?:fail|error|cannot|unable|timed out|certificate)|update\.json.{0,60}(?:corrupt|invalid|unexpected|parse)|(?:unable to|cannot|failed to) (?:reach|connect to|resolve) \S*(?:xen-orchestra\.com|nodejs\.org)|xen-orchestra\.com.{0,80}(?:ENOTFOUND|ECONNREFUSED|ETIMEDOUT|EAI_AGAIN)|getaddrinfo (?:ENOTFOUND|EAI_AGAIN) \S*(?:xen-orchestra\.com|nodejs\.org)|NODE_TLS_REJECT_UNAUTHORIZED|(?:appliance|XOA) is not registered',
     'The Xen Orchestra Appliance updater cannot complete. Run xoa check, read journalctl -u xoa-updater, and verify: registration, DNS and outbound 443 to xen-orchestra.com and nodejs.org, a TLS-intercepting proxy, free disk space, and a corrupted /var/lib/xoa-updater/update.json (delete and rerun the upgrade).',
     search='XOA update failed xoa-updater xoa check proxy TLS registration')

rule('xcp.xo_disk_full', 'Xen Orchestra: appliance or backup remote out of disk space (ENOSPC)', 'xo', 'high', ['disk-space', 'backup', 'upgrade'],
     'no space left|enospc|is full',
     r'ENOSPC|No space left on device|remote \S+ is full',
     'The XO appliance (or a backup remote) has no free space: updates, backups and logging then fail with ENOSPC. Run df -h on the appliance and the remote, free space (old backups, logs, node/yarn caches) and rerun the failed job or update.',
     search='Xen Orchestra ENOSPC no space left on device update failed backup', root_for=('xcp.xo_backup', 'xcp.xoa_update'),
     files=r'(?:xo-server|xo-web|xo-proxy|xoa|xo/|xo_server|journalctl|xo-install|xen-?orchestra)')

BY_ID = {r['id']: r for r in R}
for _r in R:
    _r['kws'] = tuple(_r['kw'].split('|'))
    _r['any_level'] = False
