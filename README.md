# LogLens Vates - targeted XCP-ng and Xen Orchestra log analysis

> **Unofficial project.** An independent, community tool, not affiliated with, endorsed by or supported by Vates. XCP-ng and Xen Orchestra are products/trademarks of their owners.
> KB links come from public web-search results (titles and URLs only; **the article text was not read**) and may be out of date. Always verify a finding against the raw log and the vendor's own documentation.
> Scenarios are anonymised and **synthetic** (invented hosts `lab.example`, `192.0.2.x`); their log lines are approximations of real error names, not real logs. No customer data is included.
> Never upload customer logs to a tool you do not control.

Analysis **driven by the reported issue and its timestamp**: everything outside the incident window is treated as noise and findings are ranked by how well they
fit the reported symptom, with root causes ranked above their downstream effects. One engine (`lvx/`, Python standard library only):

| Where | How |
|---|---|
| Windows (Python installed) | `run.bat` |
| Windows single `.exe` | `powershell -ExecutionPolicy Bypass -File build_windows.ps1` -> `dist\LogLens.exe` |
| Linux | `./run.sh`  or  `python3 -m lvx serve --host 0.0.0.0` |
| Docker / cloud | `docker build -t loglens-vates .` then `docker run -p 8765:8765 -v /bundles:/data:ro -e LVX_ROOTS=/data loglens-vates` |
| CLI / automation | `python -m lvx analyze bundle.tgz --issue "..." --time 2026-03-10T10:00:00Z --format html -o report.html` |

**Try it now:** `examples/vates/` has 6 synthetic cases (bundles, reference reports, screenshots) and `CASES.txt` (expected finding + public link per case).

## What it understands
* **Files:** XCP-ng `xensource.log`, `SMlog` (+ rotated/`.gz`), `xha.log`, `xen/hypervisor.log`, xenopsd, and generic `daemon.log` / `kern.log` / `messages` inside an
  xen-bugtool style bundle; Xen Orchestra journalctl text, `xo-server`, `xoa-updater` and installer logs. Products are detected as `xcpng` / `xo`.
  Year-less syslog lines take the incident's year.
* **25 rules** (`xcp.*`), each with a keyword prefilter, severity, advice and search phrase: dom0 disk full, xapi/toolstack down, update/RPU failure, pool master
  unreachable, HA self-fence, SR full, coalesce stuck, VDI chain too long (SR_BACKEND_FAILURE_109), SR/PBD unplugged (iSCSI/NFS), not enough memory, VM start
  failure, migration failure, XO backup failure (VDI_IO_ERROR), XO appliance/remote out of space (ENOSPC), XO TLS/self-signed certificate, XO from-sources build, XOA updater, plus storage/kernel signals: multipath path failures, LUN assignments changed, network mount stalls / hung tasks, dom0 OOM kills, tapdisk death, leaked storage datapaths, SM/kernel I/O errors and kernel faults (panic / oops / call trace / soft lockup).
* **Root vs symptom ranking:** SR full -> coalesce stuck -> chain too long / VM fails to start; disk full -> xapi down; HA fence -> master unreachable; disk full (XO) -> backup/update failure; LUN change -> multipath failures -> SR unplugged; leaked datapath / tapdisk death -> backup and VM start failures; dom0 OOM -> xapi down.

## Workflow
1. **Open** a bundle: drag in `.zip/.tgz/.tar.gz` (nested archives, rotated `.gz` logs fine), a single log file, or type a server-side path.
2. **Describe** the symptom and the **incident time** (UTC unless you give a zone). No time given -> newest log timestamp is the anchor and the last 10 days are examined.
3. **Analyze** -> ranked findings with evidence, first/last seen, sparkline, next step, KB search phrase and public links.
4. **Verify against the raw log**, per finding: *Show log context* (raw lines +-4 from the bundle file, line numbers, match highlighted; `GET /api/evidence`),
   *open in viewer* (the whole file at that line), and **Confirm / Reject / Unsure** with an optional note. Verdicts are kept in the browser (`localStorage`, per bundle + incident time),
   pushed to the server (`POST /api/jobs/<id>/verdicts`) and written into the Markdown / HTML / JSON exports ("Reviewer verdict").
5. Tabs: **Timeline**, **Log viewer** (search, regex, level filter, incident-window-only, jump to line), **Run info**. Export Markdown / HTML / JSON.

## How the noise is removed
* Time window filter - out-of-window lines are only counted, never ranked. Benign phrases (`errors: 0`, `successfully`, ...) are ignored.
* Messages are normalised (ids, IPs, numbers) and clustered, so 10 000 repeats = one finding. **Chronic** patterns spread evenly across the window are demoted.
* Ranking = rule severity + issue-topic match + keyword overlap + closeness to the incident time + volume; root causes above symptoms.

## KB research
`lvx/kb_library.json` is a dated **snapshot** of public pages returned by web search (docs.xcp-ng.org, xcp-ng.org forum/blog, xen-orchestra.com docs, github.com issues): title, URL and the
date each was seen. Causes/resolutions are what the search **summaries** stated; forum threads are community advice, not official guidance. A finding with no matching page says
**No public Vates KB found**. Add your own entries with `LVX_KB_FILE=/path/extra.json`; regenerate with `python tools/build_kb_library.py`.

## Synthetic scenarios
`python -m lvx templates list` / `show CT-53` / `build CT-53 OUT_DIR` (writes a synthetic bundle + `.tgz`). CT-50..CT-68 cover host, pool/HA, storage/SR, VM and XO problems; every one is marked
*SYNTHETIC SCENARIO built from public Vates forum/docs search summaries, not a resolved support case*. Regenerate with `python tools/build_case_templates.py`.
`tests/test_templates.py` enforces anonymisation (hash-only denylist in `tests/privacy_denylist.sha256`).

## 10-case synthetic test and performance results
`docs/ten-case-test/RESULTS.md` (generated by `python tests/ten_case_benchmark.py run`) documents a 10-case test: HA self-fence, SR/coalesce/backup cascade, multipath storm, dom0 OOM, leaked datapath, dom0 disk full,
XO certificate, XOA update ENOSPC, Rolling Pool Update memory, and a clean negative case - each with 14 days of noisy logs (0.08-0.4 M lines) and a planted incident. It records root-cause rank, secondary findings, false high/critical
findings, evidence correctness, noise removed, runtime, throughput and peak memory per case, plus a scaling check up to 1.2 M lines. `examples/ten-case-test/` has compact versions of the ten bundles and `CASES.md` (issue text, incident time, expected finding).
In-sample: same author as the rules, so it shows the pipeline works, not real-world recall.

## Credits and third-party tools
The storage/kernel rules (multipath, LUN change, mount stalls, OOM, tapdisk, leaked datapaths, I/O errors, kernel faults) and the two-tier df warning (75% early / 95% high) were
inspired by a review of the public [Fohdeesha/xcp-stuff](https://github.com/Fohdeesha/xcp-stuff) health check and repair scripts (GPL-3.0; README, `src/checks.py` and `src/config.py` were read on 2026-10-13).
No code was copied: the patterns are written independently from the underlying kernel / SM messages. The KB entries that point to that repo (including `storage-state-fixer.py`,
`snapshot-fixer.py` and `xo-config-recover.py`) are marked `basis: read`; **LogLens has not run or audited those scripts** - they change xapi/storage state, so read and test them first.

## Security notes
Binds to `127.0.0.1` by default. For shared/cloud use set `LVX_TOKEN` (bearer token), `LVX_ROOTS` (folders the server may open) or `LVX_ALLOW_OPEN=0`, and put it behind HTTPS.
Archives are unpacked to a temp dir with path-traversal/symlink protection and size caps, and deleted when the bundle is closed. Nothing is sent to any external service.

## Tests
* `python tests/test_core.py` - engine, bundles, windowing, KB library, viewer, HTTP API.
* `python tests/test_vates.py` - detection, rule hygiene, ranking, KB honesty, scenarios, accuracy gate. `tests/test_vates_api.py` - evidence / verdict API. `tests/test_vates_ui.py` - Playwright UI test + screenshots (needs node + the global `playwright` module + Chromium; skipped otherwise).
* `python tests/vates_accuracy.py` - 80 positive scenarios + 5 clean bundles x dir/tgz/nested x base/noisy profile; expected rank-1 rule per scenario; clean bundles must raise no high/critical rule finding (passes at >= 95%).
* `python tests/templates_accuracy.py` - every synthetic scenario bundle. `python tests/smoke_http.py http://127.0.0.1:8765` - end-to-end against a running server.

## Honest limits
* **In-sample accuracy.** Rules and scenarios were written by the same author; held-out phrasings were added after the first run of each round (9, then 24) and the misses fixed in the rules (2 gaps in the second round). Real-world recall is unknown until tried on real, sanitised logs - please report misses.
* Rules are generic patterns from public error names; they were not verified against real customer logs. Synthetic log lines are approximations.
* KB research is a snapshot of search summaries, not a live search and not article text.
* Year-less syslog lines assume the incident's year (or the newest log's). Naive times are UTC.
