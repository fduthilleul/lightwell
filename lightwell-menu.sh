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
        print(f'  {fam}: {len(fadv)} advisory/advisories, {len(pkgs)} package(s), {len(fcve)} CVE(s)')
    print(f'  Total: {len(total_adv)} advisory/advisories, {sum(len(p) for p in data.values())} package(s), {len(total_cve)} CVE(s)')
" | save_output "$csv"
}

q_map_github() {
  require_cache "cache_ok '$GITHUB_DIR'" "GitHub OSV" || return
  local csv; csv=$(ask_csv)
  ls "$GITHUB_DIR"/*.json | while read -r f; do
    fname=$(basename "$f"); cat "$f" | python3 -I -c "
import sys, json
d = json.load(sys.stdin)
fname = '$fname'
adv_id = d.get('id','')
schema = d.get('schema_version','')
cves   = ','.join(u for u in d.get('upstream',[]) if u.startswith('CVE-'))
for a in d.get('affected',[]):
    eco = a.get('package',{}).get('ecosystem','')
    pkg = a.get('package',{}).get('name','')
    ver = ([e['fixed'] for r in a.get('ranges',[]) for e in r.get('events',[]) if 'fixed' in e] + [''])[0]
    ver = ver or (a.get('database_specific',{}).get('lightwell',{}).get('remediated_version',''))
    print('\t'.join([fname, adv_id, schema, eco, pkg, ver, cves]))
"
  done | python3 -I -c "
import sys, os, csv as csvmod
rows = [l.strip().split('\t') for l in sys.stdin if l.strip()]
rows = [r + ['']*(7-len(r)) for r in rows if len(r)>=5]
rows.sort(key=lambda x:(x[3],x[4],x[5]))
output_csv = '$csv' == '1'
if output_csv:
    w = csvmod.writer(sys.stdout)
    w.writerow(['File','Advisory ID','OSV Schema Version','Ecosystem','Package','Remediated version','CVEs'])
    for r in rows: w.writerow(r[:7])
else:
    c=[max(len(h),max(len(r[i]) for r in rows)) for i,h in enumerate(['File','Advisory ID','OSV Schema Version','Ecosystem','Package','Remediated version','CVEs'])]
    def row(*v): return '  '+'  '.join(f'{v[i]:<{c[i]}}' for i in range(len(c)-1))+f'  {v[-1]}'
    print(row('File','Advisory ID','OSV Schema Version','Ecosystem','Package','Remediated version','CVEs'))
    print(row(*['-'*x for x in c]))
    for r in rows: print(row(*r[:7]))
    print(f'\n  Total: {len(rows)} mapping(s)')
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
        print(f'  {\"OSV files processed:\":<{lw}}  {len({r[0] for r in er})}')
        print(f'  {\"Unique CVEs fixed:\":<{lw}}  {len({c for r in er for c in r[6].split(\",\") if c})}')
        print(f'  {\"Unique novel vulns fixed:\":<{lw}}  {len({r[1] for r in er if not r[6]})}')
        print(f'  {\"Unique packages affected:\":<{lw}}  {len({r[4] for r in er})}')
        print(f'  {\"Unique versions affected:\":<{lw}}  {len({(r[4],r[5]) for r in er})}')
        print()
" | save_output "$csv"
}

q_list_packages() {
  [[ -f "$MAVEN_INDEX" ]] || { echo "  Maven index not found. Run sync-cache.sh first." >&2; return; }
  local csv; csv=$(ask_csv)
  python3 -I -c "
import json, sys, os, csv as csvmod
from collections import defaultdict
data = json.load(open('$MAVEN_INDEX'))
pkg_vers = defaultdict(set)
for e in data['entries']:
    pkg_vers[e['pkg']].add(e['version'])
rows = sorted((pkg, ', '.join(sorted(vers))) for pkg, vers in pkg_vers.items())
output_csv = '$csv' == '1'
if output_csv:
    w = csvmod.writer(sys.stdout)
    w.writerow(['Package','Remediated versions'])
    for r in rows: w.writerow(r)
else:
    c0=max(len('Package'),          max(len(r[0]) for r in rows))
    c1=max(len('Remediated versions'),max(len(r[1]) for r in rows))
    def row(a,b): return f'  {a:<{c0}}  {b}'
    print(row('Package','Remediated versions'))
    print(row('-'*c0,'-'*c1))
    for r in rows: print(row(*r))
    print(f'\n  Total: {len(rows)} package(s), {sum(len(pkg_vers[p]) for p in pkg_vers)} version(s)')
    print(f'  (index synced: {data[\"synced_at\"]})')
" | save_output "$csv"
}

q_check_artifacts() {
  [[ -f "$MAVEN_INDEX" ]] || { echo "  Maven index not found. Run sync-cache.sh first." >&2; return; }
  local csv; csv=$(ask_csv)
  python3 -I -c "
import json, sys, os, csv as csvmod
data   = json.load(open('$MAVEN_INDEX'))
entries= data['entries']
COLS   = ['jar','pom','sources_jar','test_sources_jar','cyclonedx_json','provenance_sigstore_json']
HDRS   = ['jar','pom','sources.jar','test-sources.jar','cyclonedx.json','provenance.sigstore.json']
rows   = [(e['pkg'], e['version']) + tuple('X' if e.get(c) else '-' for c in COLS)
          for e in sorted(entries, key=lambda x:(x['pkg'],x['version']))]
output_csv = '$csv' == '1'
if output_csv:
    w = csvmod.writer(sys.stdout)
    w.writerow(['Package','Version']+HDRS)
    for r in rows: w.writerow(r)
else:
    c0=max(len('Package'), max(len(r[0]) for r in rows))
    c1=max(len('Version'), max(len(r[1]) for r in rows))
    cw=[max(len(h),1) for h in HDRS]
    header = f'  {\"Package\":<{c0}}  {\"Version\":<{c1}}' + ''.join(f'  {h:^{w}}' for h,w in zip(HDRS,cw))
    sep    = f'  {\"-\"*c0}  {\"-\"*c1}' + ''.join(f'  {\"-\"*w}' for w in cw)
    print(header); print(sep)
    for r in rows:
        line = f'  {r[0]:<{c0}}  {r[1]:<{c1}}'+''.join(f'  {v:^{w}}' for v,w in zip(r[2:],cw))
        print(line)
    print(f'\n  Total: {len(rows)} version(s)')
    print(f'  Missing artifacts by category:')
    for i, h in enumerate(HDRS):
        missing = sum(1 for r in rows if r[2+i] == '-')
        label = h + ':'
        print(f'    {label:<28}  {missing}')
" | save_output "$csv"
}

q_list_added() {
  [[ -f "$MAVEN_INDEX" ]] || { echo "  Maven index not found. Run sync-cache.sh first." >&2; return; }
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
mode  = '$mode'
# Use naive datetimes throughout — Apache directory timestamps have no timezone info
now   = datetime.now()
FMT   = '%d-%b-%Y %H:%M'

if mode == 'hours':
    cutoff_from = now - timedelta(hours=float('$from_arg'))
    cutoff_to   = now + timedelta(hours=24)  # buffer: server may be ahead of VM clock
else:
    cutoff_from = datetime.strptime('$from_arg', '%Y-%m-%d')
    cutoff_to   = datetime.strptime('$to_arg',   '%Y-%m-%d') + timedelta(days=2)  # buffer

def in_window(ts_str):
    try:
        dt = datetime.strptime(ts_str.strip(), FMT)  # naive, matches Apache listing format
        return cutoff_from <= dt <= cutoff_to
    except: return False

rows = [(e['pkg'], e['version'], e['added'])
        for e in data['entries'] if in_window(e.get('added',''))]
rows.sort(key=lambda x:(x[2],x[0],x[1]))

output_csv = '$csv' == '1'
if not rows:
    print('  No packages found in the specified time window.')
    sys.exit(0)
if output_csv:
    w = csvmod.writer(sys.stdout)
    w.writerow(['Package','Version','Added'])
    for r in rows: w.writerow(r)
else:
    c0=max(len('Package'), max(len(r[0]) for r in rows))
    c1=max(len('Version'), max(len(r[1]) for r in rows))
    c2=max(len('Added'),   max(len(r[2]) for r in rows))
    def row(a,b,c): return f'  {a:<{c0}}  {b:<{c1}}  {c:<{c2}}'
    print(row('Package','Version','Added'))
    print(row('-'*c0,'-'*c1,'-'*c2))
    for r in rows: print(row(*r))
    print(f'\n  Total: {len(rows)} version(s) added, {len({r[0] for r in rows})} unique package(s)')
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
  mv_n=0
  [[ -f "$MAVEN_INDEX" ]] && mv_n=$(python3 -I -c "import json; print(len(json.load(open('$MAVEN_INDEX'))['entries']))" 2>/dev/null || echo 0)

  printf "  %-28s %s  (%s files)\n" "GitHub OSV last sync:"  "$gh_ts" "$gh_n"
  printf "  %-28s %s  (Java: %s, Python: %s files)\n" "Pulp OSV last sync:" "$po_ts" "$pj_n" "$pp_n"
  printf "  %-28s %s  (%s versions)\n" "Maven index last sync:" "$mv_ts" "$mv_n"

  echo ""
  echo "  1) Refresh cache (sync-cache.sh)"
  echo ""
  echo "  GitHub OSV"
  echo "  2) Count advisories"
  echo "  3) Count remediations (table)"
  echo "  4) Map advisories"
  echo ""
  echo "  Pulp OSV"
  echo "  5) Map Pulp OSV advisories (Java + Python)"
  echo ""
  echo "  Maven repository (Java)"
  echo "  6) List packages"
  echo "  7) Check artifact completeness"
  echo "  8) List packages added in time window"
  echo ""
  echo "  0) Exit"
  echo ""
  read -rp "Choice: " _choice

  case "$_choice" in
    1) bash "$SCRIPT_DIR/sync-cache.sh" ;;
    2) q_count_github ;;
    3) q_count_remediations ;;
    4) q_map_github ;;
    5) q_map_pulp_osv ;;
    6) q_list_packages ;;
    7) q_check_artifacts ;;
    8) q_list_added ;;
    0) echo "Bye."; exit 0 ;;
    *) echo "  Invalid choice." ;;
  esac
done
