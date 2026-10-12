#!/usr/bin/env bash
# Lightwell unified menu — queries run against local cache.
# Run sync-cache.sh first to populate the cache.

set -euo pipefail

CACHE_DIR="${LIGHTWELL_CACHE:-$HOME/.lightwell/cache}"
GITHUB_DIR="$CACHE_DIR/github-advisories"
PULP_JAVA_DIR="$CACHE_DIR/pulp-java-advisories"
PULP_PYTHON_DIR="$CACHE_DIR/pulp-python-advisories"
CHAINGUARD_DIR="$CACHE_DIR/chainguard-advisories"
MAVEN_INDEX="$CACHE_DIR/maven-index.json"
TS_FILE="$CACHE_DIR/timestamps.json"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

GREEN='\033[0;32m'
BOLD='\033[0;37m'
NC='\033[0m'

# ── Helpers ───────────────────────────────────────────────────────────────────

read_ts() {
  python3 -I -c "
import json
try:
    ts = json.load(open('$TS_FILE'))
    v = ts.get('$1', 'never')
except Exception:
    v = 'never'
print(v)
" 2>/dev/null
}

count_files() { ls "$1"/*.json 2>/dev/null | wc -l | tr -d ' '; }

cache_ok() {
  local dir="$1"
  [[ -d "$dir" ]] && [[ $(count_files "$dir") -gt 0 ]]
}

require_cache() {
  local src="$1" label="$2"
  if ! eval "$src"; then
    echo "  Cache not found for $label. Run sync-cache.sh first." >&2
    return 1
  fi
}

ask_csv() {
  read -rp "Output as CSV? [y/N] " _ans < /dev/tty
  case "$_ans" in [yY]*) echo 1 ;; *) echo 0 ;; esac
}

ask_provider() {
  echo "Provider:" >&2
  echo "  1) Lightwell" >&2
  echo "  2) Chainguard Athena" >&2
  echo "  3) Both" >&2
  read -rp "Choice [1=Lightwell / 2=Chainguard / 3=Both]: " _pr < /dev/tty >&2
  case "$_pr" in
    1) echo "lightwell" ;;
    2) echo "chainguard" ;;
    *) echo "both" ;;
  esac
}

ask_ecosystem() {
  echo "Ecosystem:" >&2
  echo "  1) Java" >&2
  echo "  2) Python" >&2
  echo "  3) Both" >&2
  read -rp "Choice [1=Java / 2=Python / 3=Both]: " _ec >&2
  case "$_ec" in
    1) echo "java" ;;
    2) echo "python" ;;
    *) echo "both" ;;
  esac
}

save_output() {
  local csv="$1"
  if [[ "$csv" == "1" ]]; then
    read -rp "Save to file? (leave empty for stdout): " _fn < /dev/tty
    if [[ -n "$_fn" ]]; then
      cat > "$_fn" && echo "Saved to $_fn" >&2
    else cat; fi
  else cat; fi
}

# ── Queries ───────────────────────────────────────────────────────────────────

q_count_github() {
  python3 -I -c "
import json, glob, os, urllib.request
from collections import Counter, defaultdict

GITHUB_DIR  = '$GITHUB_DIR'
PULP_DIRS   = ['$PULP_JAVA_DIR', '$PULP_PYTHON_DIR']
CG_DIR      = '$CHAINGUARD_DIR'
TOKEN       = os.environ.get('TOKEN', '')

def eco_label(eco_str):
    s = eco_str.lower()
    if 'maven' in s: return 'Java'
    if 'pypi'  in s or 'python' in s: return 'Python'
    return 'Unknown'

# ── Helper: count per-ecosystem from local cache files ────────────────────────
# Returns {eco: (advisories, schema, cves, unique_pkgs, unique_vers)}

def count_from_files(dirs):
    files = []
    for d in dirs:
        files += glob.glob(d + '/*.json')
    if not files:
        return None  # not synced
    eco_counts  = defaultdict(int)
    eco_schemas = defaultdict(Counter)
    eco_cves    = defaultdict(set)
    eco_pkgs    = defaultdict(set)
    eco_fixvers = defaultdict(set)
    for f in sorted(files):
        try:
            d = json.load(open(f))
        except: continue
        schema   = d.get('schema_version', 'unknown')
        all_cves = {c for c in d.get('upstream', []) + d.get('aliases', []) if c.startswith('CVE-')}
        ecos     = {eco_label(a.get('package', {}).get('ecosystem', ''))
                    for a in d.get('affected', [])}
        if not ecos: ecos = {'Unknown'}
        for eco in ecos:
            eco_counts[eco] += 1
            eco_schemas[eco][schema] += 1
            eco_cves[eco].update(all_cves)
        for a in d.get('affected', []):
            eco = eco_label(a.get('package', {}).get('ecosystem', ''))
            pkg = a.get('package', {}).get('name', '')
            if pkg:
                eco_pkgs[eco].add(pkg)
            for r in a.get('ranges', []):
                for e in r.get('events', []):
                    if 'fixed' in e and pkg:
                        eco_fixvers[eco].add((pkg, e['fixed']))
            rem = a.get('database_specific', {}).get('lightwell', {}).get('remediated_version', '')
            if rem and pkg:
                eco_fixvers[eco].add((pkg, rem))
    return {eco: (str(eco_counts[eco]),
                  ', '.join(sorted(eco_schemas[eco].keys())),
                  str(len(eco_cves[eco])),
                  str(len(eco_pkgs[eco])),
                  str(len(eco_fixvers[eco])))
            for eco in eco_counts}

# ── Helper: count per-ecosystem from Lightwell REST API ──────────────────────
# API provides package_name + fixed_versions per advisory — fully supported.
# Returns {eco: (advisories, schema, cves, unique_pkgs, unique_vers)}

def count_from_api(token):
    if not token:
        return {'(no token)': ('n/a', 'n/a', 'n/a', 'n/a', 'n/a')}
    BASE    = 'https://console.redhat.com/api/lightwell/v0.1/advisories'
    headers = {'Authorization': f'Bearer {token}'}
    eco_counts  = defaultdict(int)
    eco_schemas = defaultdict(Counter)
    eco_cves    = defaultdict(set)
    eco_pkgs    = defaultdict(set)
    eco_fixvers = defaultdict(set)
    limit, offset, total = 100, 0, None
    while True:
        req = urllib.request.Request(f'{BASE}?limit={limit}&offset={offset}', headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                d = json.load(r)
        except Exception as e:
            return {'(error)': (str(e)[:20], 'n/a', 'n/a', 'n/a', 'n/a')}
        if total is None:
            total = d['meta']['count']
        for a in d['data']:
            repo   = a.get('repository', '')
            eco    = 'Java' if 'java' in repo else 'Python' if 'python' in repo else 'Unknown'
            schema = a.get('schema_version', 'unknown')
            eco_counts[eco] += 1
            eco_schemas[eco][schema] += 1
            for c in a.get('upstream', []) + a.get('aliases', []):
                if c.startswith('CVE-'):
                    eco_cves[eco].add(c)
            pkg = a.get('package_name', '')
            if pkg:
                eco_pkgs[eco].add(pkg)
                for ver in a.get('fixed_versions', []):
                    eco_fixvers[eco].add((pkg, ver))
        offset += limit
        if offset >= total:
            break
    return {eco: (str(eco_counts[eco]),
                  ', '.join(sorted(eco_schemas[eco].keys())),
                  str(len(eco_cves[eco])),
                  str(len(eco_pkgs[eco])),
                  str(len(eco_fixvers[eco])))
            for eco in eco_counts}

# ── Build flat rows (one per source × ecosystem) ──────────────────────────────

SOURCES = [
    ('Public Lightwell OSV (GitHub)',      count_from_files([GITHUB_DIR]), 'https://github.com/project-lightwell/lightwell-osv'),
    ('Pulp OSV (packages.redhat.com)',     count_from_files(PULP_DIRS),   'https://packages.redhat.com/api/pulp-content/lightwell/osv/'),
    ('Lightwell API (console.redhat.com)', count_from_api(TOKEN),         'https://console.redhat.com/api/lightwell/v0.1/advisories'),
    ('Chainguard Athena (GitHub)',         count_from_files([CG_DIR]),    'https://github.com/chainguard-dev/athena'),
]

# flat row: (source, ecosystem, advisories, schema, cves, unique_pkgs, unique_vers, url)
flat = []
for src, eco_data, url in SOURCES:
    if eco_data is None:
        flat.append((src, 'n/a', 'not synced', 'n/a', 'n/a', 'n/a', 'n/a', url))
        continue
    for eco in ['Java', 'Python']:
        if eco in eco_data:
            cnt, schema, cves, pkgs, vers = eco_data[eco]
        else:
            cnt, schema, cves, pkgs, vers = '0', 'n/a', '0', '0', '0'
        flat.append((src, eco, cnt, schema, cves, pkgs, vers, url))
    for eco, vals in eco_data.items():
        if eco not in ('Java', 'Python'):
            flat.append((src, eco, *vals, url))

# ── Print table ───────────────────────────────────────────────────────────────

HDRS = ['Source', 'Ecosystem', 'Advisories', 'OSV schema', 'Unique CVEs', 'Unique pkgs', 'Unique vers', 'Source URL']
RIGHT = {2, 4, 5, 6}  # right-align numeric columns
c = [max(len(HDRS[i]), max(len(str(r[i])) for r in flat)) for i in range(7)]
print()
hdr_line = '  ' + '  '.join(HDRS[i].rjust(c[i]) if i in RIGHT else HDRS[i].ljust(c[i]) for i in range(7)) + '  ' + HDRS[7]
print(hdr_line)
print('  ' + '  '.join('-'*c[i] for i in range(7)) + '  ' + '-'*40)
prev_src = None
for idx, r in enumerate(flat):
    src_label = r[0] if r[0] != prev_src else ''
    prev_src  = r[0]
    line = '  ' + src_label.ljust(c[0]) + '  ' + r[1].ljust(c[1])
    for i in range(2, 7):
        line += '  ' + (str(r[i]).rjust(c[i]) if i in RIGHT else str(r[i]).ljust(c[i]))
    line += '  ' + (r[7] if src_label else '')
    print(line)
    if src_label == '' and idx < len(flat)-1 and flat[idx+1][0] != r[0]:
        print()
print()
"
}

q_count_remediations() {
  require_cache "cache_ok '$GITHUB_DIR'" "GitHub OSV" || return
  local csv; csv=$(ask_csv)
  python3 -I -c "
import sys, json, os, csv as csvmod, glob
from collections import defaultdict

GITHUB_DIR = '$GITHUB_DIR'
data = defaultdict(lambda: defaultdict(list))
adv_packages = defaultdict(set)

for fpath in sorted(glob.glob(GITHUB_DIR + '/*.json')):
    try:
        with open(fpath) as fh:
            d = json.load(fh)
    except Exception:
        continue
    adv_id = d.get('id','')
    cves   = [u for u in d.get('upstream',[]) if u.startswith('CVE-')]
    for a in d.get('affected',[]):
        eco = a.get('package',{}).get('ecosystem','')
        pkg = a.get('package',{}).get('name','')
        ver = ([e['fixed'] for r in a.get('ranges',[]) for e in r.get('events',[]) if 'fixed' in e] + [''])[0]
        ver = ver or (a.get('database_specific',{}).get('lightwell',{}).get('remediated_version',''))
        family = eco.removeprefix('Red Hat Lightwell:')
        data[family][pkg].append((adv_id, ver, cves))
        adv_packages[adv_id].add(pkg)

output_csv = '$csv' == '1'
if output_csv:
    w = csvmod.writer(sys.stdout)
    w.writerow(['Ecosystem','Package','Version','CVEs fixed'])
    for fam in sorted(data):
        for pkg in sorted(data[fam]):
            for adv_id, ver, cves in sorted(data[fam][pkg], key=lambda x:x[1]):
                w.writerow([fam, pkg, ver, ', '.join(cves)])
else:
    rows = [(fam, pkg, ver, ', '.join(cves))
            for fam in sorted(data) for pkg in sorted(data[fam])
            for adv_id, ver, cves in sorted(data[fam][pkg], key=lambda x:x[1])]
    c0=max(len('Ecosystem'), max(len(r[0]) for r in rows))
    c1=max(len('Package'),   max(len(r[1]) for r in rows))
    c2=max(len('Version'),   max(len(r[2]) for r in rows))
    c3=max(len('CVEs fixed'),max(len(r[3]) for r in rows))
    def row(a,b,c,d): return f'  {a:<{c0}}  {b:<{c1}}  {c:<{c2}}  {d}'
    print(row('Ecosystem','Package','Version','CVEs fixed'))
    print(row('-'*c0,'-'*c1,'-'*c2,'-'*c3))
    for r in rows: print(row(*r))
    print()
    total_adv = set(adv_id for pkgs in data.values() for entries in pkgs.values() for adv_id,_,_ in entries)
    total_cve = set(c for pkgs in data.values() for entries in pkgs.values() for _,_,cves in entries for c in cves)
    for fam in sorted(data):
        pkgs=data[fam]; fadv=set(a for e in pkgs.values() for a,_,_ in e); fcve=set(c for e in pkgs.values() for _,_,cv in e for c in cv)
        print(f'  {fam}: {len(fadv)} advisory/advisories, {len(pkgs)} unique package(s), {len(fcve)} unique CVE(s)')
    total_pkgs = len({pkg for pkgs in data.values() for pkg in pkgs})
    print(f'  Total: {len(total_adv)} advisory/advisories, {total_pkgs} unique package(s), {len(total_cve)} unique CVE(s)')
" | save_output "$csv"
}

q_map_github() {
  require_cache "cache_ok '$GITHUB_DIR'" "GitHub OSV" || return
  local provider; provider=$(ask_provider)
  local csv; csv=$(ask_csv)
  python3 -I -c "
import sys, json, os, csv as csvmod, glob
from collections import defaultdict

provider   = '$provider'
GITHUB_DIR = '$GITHUB_DIR'
CG_DIR     = '$CHAINGUARD_DIR'
rows       = []
eco_data   = defaultdict(lambda: {'advs': set(), 'pkgs': set(), 'cves': set()})

def parse_file(fpath, source_label):
    fname = os.path.basename(fpath)
    try:
        with open(fpath) as fh:
            d = json.load(fh)
    except Exception:
        return
    adv_id = d.get('id', '')
    schema = d.get('schema_version', '')
    # Lightwell uses 'upstream', Chainguard uses 'aliases'
    cve_list = [u for u in d.get('upstream', []) + d.get('aliases', []) if u.startswith('CVE-')]
    cves = ','.join(sorted(set(cve_list)))
    for a in d.get('affected', []):
        eco = a.get('package', {}).get('ecosystem', '')
        pkg = a.get('package', {}).get('name', '')
        ver = ([e['fixed'] for r in a.get('ranges', []) for e in r.get('events', []) if 'fixed' in e] + [''])[0]
        ver = ver or (a.get('database_specific', {}).get('lightwell', {}).get('remediated_version', ''))
        rows.append([source_label, fname, adv_id, schema, eco, pkg, ver, cves])
        family = eco.removeprefix('Red Hat Lightwell:')
        eco_data[family]['advs'].add(adv_id)
        eco_data[family]['pkgs'].add(pkg)
        eco_data[family]['cves'].update(cve_list)

if provider in ('lightwell', 'both'):
    for f in sorted(glob.glob(GITHUB_DIR + '/*.json')):
        parse_file(f, 'Lightwell')
if provider in ('chainguard', 'both'):
    for f in sorted(glob.glob(CG_DIR + '/*.json')):
        parse_file(f, 'Chainguard')

rows.sort(key=lambda x: (x[0], x[4], x[5], x[6]))
output_csv = '$csv' == '1'

if not rows:
    print('  No data. Run sync-cache.sh to populate cache.')
    sys.exit(0)

show_provider = provider == 'both'
HDRS = (['Provider'] if show_provider else []) + ['File', 'Advisory ID', 'OSV Schema Version', 'Ecosystem', 'Package', 'Remediated version', 'CVEs']
data_rows = [([r[0]] if show_provider else []) + r[1:] for r in rows]

if output_csv:
    w = csvmod.writer(sys.stdout)
    w.writerow(HDRS)
    for r in data_rows: w.writerow(r)
else:
    c = [max(len(h), max(len(str(r[i])) for r in data_rows)) for i, h in enumerate(HDRS)]
    def fmt(*v): return '  ' + '  '.join(f'{str(v[i]):<{c[i]}}' for i in range(len(c)-1)) + f'  {v[-1]}'
    print(fmt(*HDRS))
    print(fmt(*['-'*x for x in c]))
    for r in data_rows: print(fmt(*r))
    print()
    for fam in sorted(eco_data):
        ed = eco_data[fam]
        nadv = len(ed['advs']); npkg = len(ed['pkgs']); ncve = len(ed['cves'])
        print(f'  {fam}: {nadv} advisory/advisories, {npkg} unique package(s), {ncve} unique CVE(s)')
    all_advs = {a for ed in eco_data.values() for a in ed['advs']}
    all_pkgs = {p for ed in eco_data.values() for p in ed['pkgs']}
    all_cves = {c for ed in eco_data.values() for c in ed['cves']}
    print(f'  Total: {len(all_advs)} advisory/advisories, {len(all_pkgs)} unique package(s), {len(all_cves)} unique CVE(s)')
" | save_output "$csv"
}

q_map_pulp_osv() {
  require_cache "cache_ok '$PULP_JAVA_DIR'" "Pulp OSV" || return
  local csv; csv=$(ask_csv)
  for eco_dir in "$PULP_JAVA_DIR" "$PULP_PYTHON_DIR"; do
    [[ -d "$eco_dir" ]] || continue
    ls "$eco_dir"/*.json 2>/dev/null | while read -r f; do
      fname=$(basename "$f"); cat "$f" | python3 -I -c "
import sys, json
d = json.load(sys.stdin)
fname  = '$fname'
adv_id = d.get('id','')
schema = d.get('schema_version','')
cves   = ','.join(sorted(set(
  [u for u in d.get('aliases',[]) if u.startswith('CVE-')] +
  [u for u in d.get('upstream',[]) if u.startswith('CVE-')])))
for a in d.get('affected',[]):
    eco = a.get('package',{}).get('ecosystem','')
    pkg = a.get('package',{}).get('name','')
    ver = ([e['fixed'] for r in a.get('ranges',[]) for e in r.get('events',[]) if 'fixed' in e] + [''])[0]
    ver = ver or (a.get('database_specific',{}).get('lightwell',{}).get('remediated_version',''))
    print('\t'.join([fname, adv_id, schema, eco, pkg, ver, cves]))
"
    done
  done | python3 -I -c "
import sys, os, csv as csvmod
from collections import defaultdict
rows = [l.strip().split('\t') for l in sys.stdin if l.strip()]
rows = [r + ['']*(7-len(r)) for r in rows if len(r)>=5]
rows.sort(key=lambda x:(x[3],x[4],x[5]))
output_csv = '$csv' == '1'
ECO_LABEL={'Maven':'Java','PyPI':'Python'}
if output_csv:
    w = csvmod.writer(sys.stdout)
    w.writerow(['File','Advisory ID','OSV Schema Version','Ecosystem','Package','Remediated version','CVEs'])
    for r in rows: w.writerow(r[:7])
else:
    if not rows: print('No data.'); sys.exit(0)
    c=[max(len(h),max(len(r[i]) for r in rows)) for i,h in enumerate(['File','Advisory ID','OSV Schema Version','Ecosystem','Package','Remediated version','CVEs'])]
    def row(*v): return '  '+'  '.join(f'{v[i]:<{c[i]}}' for i in range(len(c)-1))+f'  {v[-1]}'
    print(row('File','Advisory ID','OSV Schema Version','Ecosystem','Package','Remediated version','CVEs'))
    print(row(*['-'*x for x in c]))
    for r in rows: print(row(*r[:7]))
    print()
    by_eco=defaultdict(list)
    for r in rows: by_eco[r[3]].append(r)
    lw=max(len('OSV files processed:'),len('Unique CVEs fixed:'),len('Unique packages affected:'),len('Unique versions affected:'))
    for eco in sorted(by_eco):
        er=by_eco[eco]
        print(ECO_LABEL.get(eco,eco))
        n_osv = len({r[0] for r in er})
        n_cve = len({c for r in er for c in r[6].split(',') if c})
        n_nov = len({r[1] for r in er if not r[6]})
        n_pkg = len({r[4] for r in er})
        n_ver = len({(r[4],r[5]) for r in er})
        print('  ' + 'OSV files processed:'.ljust(lw)       + '  ' + str(n_osv))
        print('  ' + 'Unique CVEs fixed:'.ljust(lw)         + '  ' + str(n_cve))
        print('  ' + 'Unique novel vulns fixed:'.ljust(lw)  + '  ' + str(n_nov))
        print('  ' + 'Unique packages affected:'.ljust(lw)  + '  ' + str(n_pkg))
        print('  ' + 'Unique versions affected:'.ljust(lw)  + '  ' + str(n_ver))
        print()
" | save_output "$csv"
}

q_list_packages() {
  [[ -f "$MAVEN_INDEX" ]] || { echo "  Package index not found. Run sync-cache.sh first." >&2; return; }
  local eco; eco=$(ask_ecosystem)
  local csv; csv=$(ask_csv)
  python3 -I -c "
import json, sys, os, csv as csvmod
from collections import defaultdict
data = json.load(open('$MAVEN_INDEX'))
eco  = '$eco'
entries = [e for e in data['entries'] if eco == 'both' or e.get('ecosystem', 'java') == eco]
pkg_vers = defaultdict(set)
for e in entries:
    pkg_vers[e['pkg']].add(e['version'])
rows = sorted((pkg, ', '.join(sorted(vers))) for pkg, vers in pkg_vers.items())
output_csv = '$csv' == '1'
if not rows:
    print('  No packages found for the selected ecosystem.')
    sys.exit(0)
if output_csv:
    w = csvmod.writer(sys.stdout)
    w.writerow(['Package','Remediated versions'])
    for r in rows: w.writerow(r)
else:
    c0=max(len('Package'),            max(len(r[0]) for r in rows))
    c1=max(len('Remediated versions'),max(len(r[1]) for r in rows))
    def row(a,b): return f'  {a:<{c0}}  {b}'
    print(row('Package','Remediated versions'))
    print(row('-'*c0,'-'*c1))
    for r in rows: print(row(*r))
    print(f'\n  Total: {len(rows)} package(s), {sum(len(pkg_vers[p]) for p in pkg_vers)} version(s)')
    print('  (index synced: ' + data['synced_at'] + ')')
" | save_output "$csv"
}

q_check_artifacts() {
  [[ -f "$MAVEN_INDEX" ]] || { echo "  Package index not found. Run sync-cache.sh first." >&2; return; }
  local eco; eco=$(ask_ecosystem)
  local csv; csv=$(ask_csv)
  python3 -I -c "
import json, sys, os, csv as csvmod
data = json.load(open('$MAVEN_INDEX'))
eco  = '$eco'
output_csv = '$csv' == '1'

JAVA_COLS   = ['jar','pom','sources_jar','test_sources_jar','cyclonedx_json','provenance_sigstore_json']
JAVA_HDRS   = ['jar','pom','sources.jar','test-sources.jar','cyclonedx.json','provenance.sigstore.json']
PYTHON_COLS = ['whl','tar_gz','cyclonedx_json','provenance_sigstore_json']
PYTHON_HDRS = ['whl','tar.gz','cyclonedx.json','provenance.sigstore.json']

def show_section(entries, cols, hdrs, eco_label):
    rows = [(e['pkg'], e['version']) + tuple('X' if e.get(c) else '-' for c in cols)
            for e in sorted(entries, key=lambda x:(x['pkg'],x['version']))]
    if not rows:
        print('  No ' + eco_label + ' entries.')
        return
    if output_csv:
        w = csvmod.writer(sys.stdout)
        w.writerow(['Package','Version']+hdrs)
        for r in rows: w.writerow(r)
    else:
        print('  ' + eco_label)
        c0 = max(len('Package'), max(len(r[0]) for r in rows))
        c1 = max(len('Version'), max(len(r[1]) for r in rows))
        cw = [max(len(h), 1) for h in hdrs]
        header = '  ' + 'Package'.ljust(c0) + '  ' + 'Version'.ljust(c1)
        for h, w in zip(hdrs, cw):
            header += '  ' + h.center(w)
        sep = '  ' + '-'*c0 + '  ' + '-'*c1
        for w in cw:
            sep += '  ' + '-'*w
        print(header)
        print(sep)
        for r in rows:
            line = '  ' + r[0].ljust(c0) + '  ' + r[1].ljust(c1)
            for v, w in zip(r[2:], cw):
                line += '  ' + v.center(w)
            print(line)
        print()
        print('  Total: ' + str(len(rows)) + ' version(s)')
        print('  Missing artifacts by category:')
        for i, h in enumerate(hdrs):
            missing = sum(1 for r in rows if r[2+i] == '-')
            lbl = h + ':'
            print('    ' + lbl.ljust(28) + '  ' + str(missing))
        print()

all_entries = data['entries']
if eco in ('java', 'both'):
    show_section([e for e in all_entries if e.get('ecosystem','java')=='java'], JAVA_COLS, JAVA_HDRS, 'Java')
if eco in ('python', 'both'):
    show_section([e for e in all_entries if e.get('ecosystem')=='python'], PYTHON_COLS, PYTHON_HDRS, 'Python')
" | save_output "$csv"
}

q_list_added() {
  [[ -f "$MAVEN_INDEX" ]] || { echo "  Package index not found. Run sync-cache.sh first." >&2; return; }
  local eco; eco=$(ask_ecosystem)
  echo "Time filter:"
  echo "  1) Last N hours"
  echo "  2) Between two dates"
  read -rp "Choice [1/2]: " _tc
  local mode from_arg to_arg
  case "$_tc" in
    1) read -rp "Last how many hours? " _h; mode="hours"; from_arg="$_h"; to_arg="" ;;
    2) read -rp "Start date (YYYY-MM-DD): " _f; read -rp "End date (YYYY-MM-DD): " _t
       mode="range"; from_arg="$_f"; to_arg="$_t" ;;
    *) echo "Invalid."; return ;;
  esac
  local csv; csv=$(ask_csv)
  python3 -I -c "
import json, sys, os, csv as csvmod
from datetime import datetime, timedelta

data  = json.load(open('$MAVEN_INDEX'))
eco   = '$eco'
mode  = '$mode'
now   = datetime.now()
FMT   = '%d-%b-%Y %H:%M'

if mode == 'hours':
    cutoff_from = now - timedelta(hours=float('$from_arg'))
    cutoff_to   = now + timedelta(hours=24)
else:
    cutoff_from = datetime.strptime('$from_arg', '%Y-%m-%d')
    cutoff_to   = datetime.strptime('$to_arg',   '%Y-%m-%d') + timedelta(days=2)

def in_window(ts_str):
    try:
        dt = datetime.strptime(ts_str.strip(), FMT)
        return cutoff_from <= dt <= cutoff_to
    except: return False

entries = [e for e in data['entries'] if eco == 'both' or e.get('ecosystem','java') == eco]
rows = [(e.get('ecosystem','java').capitalize(), e['pkg'], e['version'], e['added'])
        for e in entries if in_window(e.get('added',''))]
rows.sort(key=lambda x:(x[3],x[1],x[2]))

output_csv = '$csv' == '1'
if not rows:
    print('  No packages found in the specified time window.')
    sys.exit(0)
if output_csv:
    w = csvmod.writer(sys.stdout)
    w.writerow(['Ecosystem','Package','Version','Added'])
    for r in rows: w.writerow(r)
else:
    c0=max(len('Ecosystem'),max(len(r[0]) for r in rows))
    c1=max(len('Package'),  max(len(r[1]) for r in rows))
    c2=max(len('Version'),  max(len(r[2]) for r in rows))
    c3=max(len('Added'),    max(len(r[3]) for r in rows))
    def row(a,b,c,d): return f'  {a:<{c0}}  {b:<{c1}}  {c:<{c2}}  {d:<{c3}}'
    print(row('Ecosystem','Package','Version','Added'))
    print(row('-'*c0,'-'*c1,'-'*c2,'-'*c3))
    for r in rows: print(row(*r))
    print(f'\n  Total: {len(rows)} version(s) added, {len({r[1] for r in rows})} unique package(s)')
" | save_output "$csv"
}

q_api_packages() {
  if [[ -z "${TOKEN:-}" ]]; then
    echo "  No TOKEN set. Run: export TOKEN=\$(lw_token)" >&2
    return
  fi

  # Validate token before asking any questions
  local _http_code
  _http_code=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $TOKEN" \
    'https://console.redhat.com/api/lightwell/v0.1/packages?limit=1')
  case "$_http_code" in
    200) ;;
    401) echo "  Token expired (HTTP 401). Refresh with: export TOKEN=\$(lw_token)" >&2; return ;;
    403) echo "  Access denied (HTTP 403). Check your Red Hat account permissions." >&2; return ;;
    *)   echo "  API unreachable (HTTP $_http_code). Check your connection." >&2; return ;;
  esac

  local csv; csv=$(ask_csv)
  local outfile=""
  if [[ "$csv" == "1" ]]; then
    read -rp "Filename (without extension): " _fn < /dev/tty
    outfile="${_fn:-lightwell-packages}.csv"
  fi
  export outfile
  python3 -I -c "
import json, os, sys, urllib.request, urllib.error, csv as csvmod

TOKEN      = os.environ.get('TOKEN', '')
BASE       = 'https://console.redhat.com/api/lightwell/v0.1/packages'
headers    = {'Authorization': f'Bearer {TOKEN}'}
OUTPUT_CSV = '$csv' == '1'
OUTFILE    = os.environ.get('outfile', '')

def api_get(params, limit=1, offset=0):
    p = dict(params)
    p['limit'] = limit; p['offset'] = offset
    qs  = '&'.join(f'{k}={v}' for k, v in p.items())
    req = urllib.request.Request(f'{BASE}?{qs}', headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        sys.stderr.write(f'  API error: HTTP {e.code} {e.reason}\n')
        return None
    except Exception as e:
        sys.stderr.write(f'  API error: {e}\n')
        return None

def fetch_count(params):
    d = api_get(params, limit=1)
    return d['meta']['count'] if d else '?'

def fetch_all(eco, level):
    results, limit, offset, total = [], 100, 0, None
    while True:
        d = api_get({'ecosystem': eco, 'security_level': level}, limit=limit, offset=offset)
        if d is None: break
        if total is None: total = d['meta']['count']
        results.extend(d['data'])
        offset += limit
        sys.stderr.write(f'\r  [{eco}/{level}] {len(results)}/{total}   ')
        if offset >= total: break
    sys.stderr.write('\n')
    return results

# ── Summary counts ────────────────────────────────────────────────────────────

sys.stderr.write('  Fetching counts from Lightwell API...\n')

COMBOS = [
    ('Java',   'maven',  'remediated'),
    ('Java',   'maven',  'validated'),
    ('Python', 'python', 'remediated'),
    ('Python', 'python', 'validated'),
]
counts      = {(lbl, lvl): fetch_count({'ecosystem': eco, 'security_level': lvl}) for lbl, eco, lvl in COMBOS}
total_count = fetch_count({})

# ── Print summary table ───────────────────────────────────────────────────────

ROWS = [(lbl, lvl.capitalize(), str(counts[(lbl, lvl)])) for lbl, _, lvl in COMBOS]
c0   = max(len('Ecosystem'),      max(len(r[0]) for r in ROWS))
c1   = max(len('Security level'), max(len(r[1]) for r in ROWS))
c2   = max(len('Packages'),       max(len(r[2]) for r in ROWS), len(str(total_count)))

def fmt(a, b, c): return f'  {a:<{c0}}  {b:<{c1}}  {c:>{c2}}'

print()
print(fmt('Ecosystem', 'Security level', 'Packages'))
print(fmt('-'*c0, '-'*c1, '-'*c2))
prev = None
for lbl, _, lvl in COMBOS:
    label = lbl if lbl != prev else ''
    prev  = lbl
    print(fmt(label, lvl.capitalize(), str(counts[(lbl, lvl)])))
print('  ' + '-' * (c0 + c1 + c2 + 6))
print(fmt('Total', '', str(total_count)))
print()

if not OUTPUT_CSV:
    sys.exit(0)

# ── Fetch all and write CSV ───────────────────────────────────────────────────

sys.stderr.write('  Fetching all packages for CSV export...\n')
all_rows = []
for lbl, eco, lvl in COMBOS:
    for p in fetch_all(eco, lvl):
        name       = p.get('name', '')
        group      = p.get('group', '')
        repository = p.get('repository', '')
        versions   = ', '.join(p.get('versions', []))
        lr         = p.get('latest_releases', [])
        latest     = lr[0].get('version',    '') if lr else ''
        release    = lr[0].get('release',    '') if lr else ''
        created_at = lr[0].get('created_at', '') if lr else ''
        all_rows.append((lbl, lvl.capitalize(), group, name, repository, versions, latest, release, created_at))

all_rows.sort(key=lambda x: (x[0], x[1], x[2], x[3]))

with open(OUTFILE, 'w', newline='') as f:
    w = csvmod.writer(f)
    w.writerow(['Ecosystem', 'Security Level', 'Group', 'Package', 'Repository',
                'Versions', 'Latest Version', 'Latest Release', 'Published At'])
    w.writerows(all_rows)

print(f'  {len(all_rows)} packages saved to {OUTFILE}')
"
}

# ── Main menu loop ────────────────────────────────────────────────────────────

while true; do
  echo ""
  echo "Lightwell Tools"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  Cache: $CACHE_DIR"
  echo ""

  gh_ts=$(read_ts github)
  gh_n=$( cache_ok "$GITHUB_DIR"   && count_files "$GITHUB_DIR"   || echo 0)
  po_ts=$(read_ts pulp_osv)
  pj_n=$( cache_ok "$PULP_JAVA_DIR" && count_files "$PULP_JAVA_DIR" || echo 0)
  pp_n=$( cache_ok "$PULP_PYTHON_DIR" && count_files "$PULP_PYTHON_DIR" || echo 0)
  mv_ts=$(read_ts maven)
  mv_info="none"
  [[ -f "$MAVEN_INDEX" ]] && mv_info=$(python3 -I -c "
import json
try:
    e=json.load(open('$MAVEN_INDEX'))['entries']
    j=sum(1 for x in e if x.get('ecosystem','java')=='java')
    p=sum(1 for x in e if x.get('ecosystem')=='python')
    print(f'Java: {j}, Python: {p} versions')
except: print('none')
" 2>/dev/null || echo "none")

  printf "  %-28s %s  (%s files)\n"              "GitHub OSV last sync:"   "$gh_ts" "$gh_n"
  printf "  %-28s %s  (Java: %s, Python: %s files)\n" "Pulp OSV last sync:" "$po_ts" "$pj_n" "$pp_n"
  printf "  %-28s %s  (%s)\n"                    "Package index last sync:" "$mv_ts" "$mv_info"

  echo ""
  printf "  ${BOLD}1) Refresh cache (sync-cache.sh)${NC}\n"
  echo ""
  printf "  ${GREEN}Lightwell OSV Security Advisories${NC}\n"
  echo "  Source: https://github.com/project-lightwell/lightwell-osv/"
  echo ""
  printf "  ${BOLD}2) Count advisories - how many OSV files ?${NC}\n"
  printf "  ${BOLD}3) Display advisories (table) - Advisory ID, package, unique packages and CVEs per ecosystem${NC}\n"
  echo ""
  printf "  ${GREEN}Lightwell Remediated Packages OSV${NC}\n"
  echo "  Source for Java:   https://packages.redhat.com/api/pulp-content/lightwell/osv/java/remediated/"
  echo "  Source for Python: https://packages.redhat.com/api/pulp-content/lightwell/osv/python/remediated/"
  echo ""
  printf "  ${BOLD}4) Display Pulp OSV advisories (Java + Python)${NC}\n"
  echo ""
  printf "  ${GREEN}Lightwell Remediated repositories${NC}\n"
  echo "  Source: https://packages.redhat.com/lightwell/java/remediated/"
  echo "  Source: https://packages.redhat.com/lightwell/python/remediated/"
  echo ""
  printf "  ${BOLD}5) List packages${NC}\n"
  printf "  ${BOLD}6) Check artifact completeness${NC}\n"
  printf "  ${BOLD}7) List packages added in time window${NC}\n"
  echo ""
  printf "  ${GREEN}Lightwell Network API  (live — requires \$TOKEN)${NC}\n"
  echo ""
  printf "  ${BOLD}8) Extract packages — remediated & validated summary + CSV${NC}\n"
  echo ""
  printf "  ${BOLD}0) Exit${NC}\n"
  echo ""
  read -rp "Choice: " _choice

  case "$_choice" in
    1) bash "$SCRIPT_DIR/sync-cache.sh" ;;
    2) q_count_github ;;
    3) q_map_github ;;
    4) q_map_pulp_osv ;;
    5) q_list_packages ;;
    6) q_check_artifacts ;;
    7) q_list_added ;;
    8) q_api_packages ;;
    0) echo "Bye."; exit 0 ;;
    *) echo "  Invalid choice." ;;
  esac
done
