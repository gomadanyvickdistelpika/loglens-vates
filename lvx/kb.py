"""KB research attached to every finding: public Vates / XCP-ng / Xen Orchestra pages.

Data comes from lvx/kb_library.json: a dated SNAPSHOT of web-search results (title + URL + the date each page was seen) with the cause/resolution
text that the search-result SUMMARIES stated.  The article text itself was NOT read.  Optional extra entries come from the file named by LVX_KB_FILE.
This is NOT a live lookup.  When nothing in the library matches a finding the result says 'No public Vates KB found' instead of guessing."""
import json
import os
import re

_LIB = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'kb_library.json')
VENDOR = 'Vates/XCP-ng'
MAX_SHOWN = 4
_cache = None


def article_url(aid):
    aid = str(aid)
    if not aid.startswith('https://'):
        raise ValueError('article ids are full https URLs: %r' % aid)
    return aid


def _load():
    global _cache
    if _cache is not None:
        return _cache
    with open(_LIB, encoding='utf-8') as f:
        lib = json.load(f)
    extra = os.environ.get('LVX_KB_FILE')
    if extra and os.path.isfile(extra):
        try:
            with open(extra, encoding='utf-8') as f:
                lib['entries'] = lib['entries'] + json.load(f).get('entries', [])
        except (OSError, ValueError):
            pass                      # a broken user file must never break an analysis
    for e in lib['entries']:
        e['_rx'] = re.compile(e['match'], re.I) if e.get('match') else None
    _cache = lib
    return lib


def reset_cache():
    global _cache
    _cache = None


def library_info():
    lib = _load()
    return dict(researched=lib['researched'], source=lib['source'], entries=len(lib['entries']))


_HOSTS = {'github.com': 'GitHub', 'xen-orchestra.com': 'Xen Orchestra', 'docs.xen-orchestra.com': 'Xen Orchestra docs', 'docs.xcp-ng.org': 'XCP-ng docs',
          'xcp-ng.org': 'XCP-ng forum/blog'}


def _art(a):
    """Article dict for output: the page's site as a label, the full URL and the date it appeared in a search."""
    url = article_url(a['id'])
    host = url.split('/')[2]
    label = _HOSTS.get(host, host)
    if host == 'xcp-ng.org' and '/forum/' not in url:
        label = 'XCP-ng site'
    return dict(id=url, title=a['title'], url=url, label=label, seen=a.get('seen', ''))


def _entry_out(e, precision):
    return dict(topic=e['topic'], precision=precision, cause=e.get('cause', ''), resolution=e.get('resolution', []),
                notes=e.get('notes', ''), basis=e.get('basis', 'summary'), articles=[_art(a) for a in e['articles']])


def _template_entries(rule_id, text):
    """Entries from the synthetic scenarios whose expected rule matches this finding."""
    if not rule_id:
        return []
    from . import templates
    out = []
    for t in templates.all_templates():
        if rule_id not in t['expect_rules']:
            continue
        if t.get('match') and not re.search(t['match'], text or '', re.I):
            continue
        out.append(dict(topic='Scenario %s: %s' % (t['id'], t['title']), precision='case-template', cause=t.get('cause', ''),
                        resolution=t.get('resolution', []), notes=t.get('notes', ''), basis='case',
                        articles=[_art(k) for k in t.get('kb', []) if k.get('role') != 'noise'],
                        template=t['id'], evidence=t.get('evidence', ''), synthetic='SYNTHETIC SCENARIO' in (t.get('notes') or '')))
    return out


def research(rule_id, text, search_phrase=None, kind='rule'):
    """Return {'status': 'found'|'none', 'entries': [...], 'more': n, 'searched': phrase, 'message': str, 'vendor': ...}."""
    lib = _load()
    base = dict(library_date=lib['researched'], searched=search_phrase or '', vendor=VENDOR)
    if kind == 'generic' or not rule_id:
        return dict(base, status='none', entries=[], more=0,
                    message='No public Vates KB found: this message matches no known signature, so it was not researched. Use the search phrase manually.')
    tmpl = _template_entries(rule_id, text)
    hit, general = [], []                     # (priority, entry) - higher priority first, library order otherwise
    for e in lib['entries']:
        if rule_id not in e['rules']:
            continue
        if e['_rx'] is None:
            general.append((e.get('priority', 0), _entry_out(e, 'general')))
        elif e['_rx'].search(text or ''):
            hit.append((e.get('priority', 0), _entry_out(e, 'match')))
    ents = tmpl + [x for _p, x in sorted(hit, key=lambda t: -t[0])] + [x for _p, x in sorted(general, key=lambda t: -t[0])]
    if not ents:
        return dict(base, status='none', entries=[], more=0,
                    message='No public Vates KB found in the LogLens KB library for this finding (researched %s; search summaries only, no article text read). '
                            'Try the search phrase manually on docs.xcp-ng.org, docs.xen-orchestra.com and the XCP-ng forum.' % lib['researched'])
    return dict(base, status='found', entries=ents[:MAX_SHOWN], more=max(0, len(ents) - MAX_SHOWN),
                message='Matched from the LogLens KB library%s (public pages seen %s in web-search results, not a live search). '
                        'Search-result summaries only; the article text was not read, except where an entry\'s note says the page itself was read.' % (' and the synthetic scenarios' if tmpl else '', lib['researched']))
