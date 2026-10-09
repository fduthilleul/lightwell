#!/usr/bin/env bash
# Lightwell unified menu — queries run against local cache.
# Run sync-cache.sh first to populate the cache.

set -euo pipefail

CACHE_DIR="${LIGHTWELL_CACHE:-$HOME/.lightwell/cache}"
GITHUB_DIR="$CACHE_DIR/github-advisories"
PULP_JAVA_DIR="$CACHE_DIR/pulp-java-advisories"
PULP_PYTHON_DIR="$CACHE_DIR/pulp-python-advisories"
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
  read -rp "Output as CSV? [y/N] " _ans
  case "$_ans" in [yY]*) echo 1 ;; *) echo 0 ;; esac
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
    read -rp "Save to file? (leave empty for stdout): " _fn
    if [[ -n "$_fn" ]]; then
      cat > "$_fn" && echo "Saved to $_fn" >&2
    else cat; fi
  else cat; fi
}

# ── Queries ───────────────────────────────────────────────────────────────────

q_count_github() {
  require_cache "cache_ok '$GITHUB_DIR'" "GitHub OSV" || return
  local n; n=$(count_files "$GITHUB_DIR")
  echo ""
  echo "  GitHub OSV advisory files in cache: $n"
  echo ""
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
  local csv; csv=$(ask_csv)
  python3 -I -c "
import sys, json, os, csv as csvmod, glob
from collections import defaultdict

GITHUB_DIR = '$GITHUB_DIR'
rows = []
eco_data = defaultdict(lambda: {'advs': set(), 'pkgs': set(), 'cves': set()})

for fpath in sorted(glob.glob(GITHUB_DIR + '/*.json')):
    fname = os.path.basename(fpath)
    try:
        with open(fpath) as fh:
            d = json.load(fh)
    except Exception:
        continue
    adv_id   = d.get('id', '')
    schema   = d.get('schema_version', '')
    cve_list = [u for u in d.get('upstream', []) if u.startswith('CVE-')]
    cves     = ','.join(cve_list)
    for a in d.get('affected', []):
        eco = a.get('package', {}).get('ecosystem', '')
        pkg = a.get('package', {}).get('name', '')
        ver = ([e['fixed'] for r in a.get('ranges', []) for e in r.get('events', []) if 'fixed' in e] + [''])[0]
        ver = ver or (a.get('database_specific', {}).get('lightwell', {}).get('remediated_version', ''))
        rows.append([fname, adv_id, schema, eco, pkg, ver, cves])
        family = eco.removeprefix('Red Hat Lightwell:')
        eco_data[family]['advs'].add(adv_id)
        eco_data[family]['pkgs'].add(pkg)
        eco_data[family]['cves'].update(cve_list)

rows.sort(key=lambda x: (x[3], x[4], x[5]))
output_csv = '$csv' == '1'

if not rows:
    print('No data.')
    sys.exit(0)

HDRS = ['File', 'Advisory ID', 'OSV Schema Version', 'Ecosystem', 'Package', 'Remediated version', 'CVEs']
if output_csv:
    w = csvmod.writer(sys.stdout)
    w.writerow(HDRS)
    for r in rows: w.writerow(r[:7])
else:
    c = [max(len(h), max(len(r[i]) for r in rows)) for i, h in enumerate(HDRS)]
    def fmt(*v): return '  ' + '  '.join(f'{v[i]:<{c[i]}}' for i in range(len(c)-1)) + f'  {v[-1]}'
    print(fmt(*HDRS))
    print(fmt(*['-'*x for x in c]))
    for r in rows: print(fmt(*r[:7]))
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
    0) echo "Bye."; exit 0 ;;
    *) echo "  Invalid choice." ;;
  esac
done
