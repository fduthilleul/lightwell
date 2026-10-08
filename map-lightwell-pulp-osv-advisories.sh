#!/usr/bin/env bash
# Map advisory files from packages.redhat.com Lightwell OSV endpoints (Java + Python)
# to ecosystem, package, remediated version and CVEs.

set -euo pipefail

ENDPOINTS=(
  "https://packages.redhat.com/api/pulp-content/lightwell/osv/java/remediated"
  "https://packages.redhat.com/api/pulp-content/lightwell/osv/python/remediated"
)

# Ask for credentials only if not already set in the environment.
# Tip: run 'export _user _pass' in your shell to skip these prompts.
if [[ -z "${_user:-}" ]]; then
  read -rp "Username: " _user
fi
if [[ -z "${_pass:-}" ]]; then
  read -rsp "Password: " _pass
  echo
fi
export _user _pass

read -rp "Output as CSV? [y/N] " _answer
case "$_answer" in
  [yY]*)
    export OUTPUT_CSV=1
    read -rp "Save to file? (leave empty for stdout): " _filename
    ;;
  *)
    export OUTPUT_CSV=0
    _filename=""
    ;;
esac

{
for BASE_URL in "${ENDPOINTS[@]}"; do
  curl -sL -u "$_user:$_pass" "$BASE_URL/" \
  | grep -oE 'x_RHLW-[^"]+\.json' | sort -u \
  | while read -r f; do
      curl -sL -u "$_user:$_pass" "$BASE_URL/$f" | jq -r \
        --arg fname "$f" \
        '([.aliases[]? | select(startswith("CVE-"))]
          + [.upstream[]? | select(startswith("CVE-"))] | unique) as $cves
         | .schema_version as $schema
         | .id as $id
         | .affected[]
         | [
             $fname,
             $id,
             $schema,
             .package.ecosystem,
             .package.name,
             (
               ([(.ranges // [])[] | .events[]? | select(has("fixed")) | .fixed][0])
               // .database_specific?.lightwell?.remediated_version
               // ""
             ),
             ($cves | join(","))
           ]
         | @tsv'
    done
done \
| python3 -I -c "
import sys, os, csv as csvmod

rows = []
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    parts = line.split('\t')
    if len(parts) < 6:
        continue
    rows.append(parts[:7] if len(parts) >= 7 else parts[:6] + [''])

output_csv = os.environ.get('OUTPUT_CSV', '0') == '1'

if not rows:
    print('No data retrieved.', file=sys.stderr)
    sys.exit(1)

if output_csv:
    writer = csvmod.writer(sys.stdout)
    writer.writerow(['File', 'Advisory ID', 'OSV Schema Version', 'Ecosystem', 'Package', 'Remediated version', 'CVEs'])
    for r in sorted(rows, key=lambda x: (x[3], x[4], x[5])):
        writer.writerow(r)
else:
    col0 = max(len('File'),                 max(len(r[0]) for r in rows))
    col1 = max(len('Advisory ID'),          max(len(r[1]) for r in rows))
    col2 = max(len('OSV Schema Version'),   max(len(r[2]) for r in rows))
    col3 = max(len('Ecosystem'),            max(len(r[3]) for r in rows))
    col4 = max(len('Package'),              max(len(r[4]) for r in rows))
    col5 = max(len('Remediated version'),   max(len(r[5]) for r in rows))
    col6 = max(len('CVEs'),                 max(len(r[6]) for r in rows))

    def row(a, b, c, d, e, f, g=''):
        return f'  {a:<{col0}}  {b:<{col1}}  {c:<{col2}}  {d:<{col3}}  {e:<{col4}}  {f:<{col5}}  {g}'

    print(row('File', 'Advisory ID', 'OSV Schema Version', 'Ecosystem', 'Package', 'Remediated version', 'CVEs'))
    print(row('-'*col0, '-'*col1, '-'*col2, '-'*col3, '-'*col4, '-'*col5, '-'*col6))
    for r in sorted(rows, key=lambda x: (x[3], x[4], x[5])):
        print(row(*r))

    print()

# Summary (both modes)
from collections import defaultdict

ECO_LABEL = {'Maven': 'Java', 'PyPI': 'Python'}

# Group rows by ecosystem
by_eco = defaultdict(list)
for r in rows:
    by_eco[r[3]].append(r)

label_w = max(len('OSV files processed:'), len('Unique CVEs fixed:'),
              len('Unique novel vulns fixed:'), len('Unique packages affected:'),
              len('Unique versions affected:'))

def summary_line(label, value):
    return f'  {label:<{label_w}}  {value}'

ecosystems = sorted(by_eco)
for eco in ecosystems:
    eco_rows = by_eco[eco]
    osv_files    = len({r[0] for r in eco_rows})
    cves         = {c for r in eco_rows for c in r[6].split(',') if c}
    novel        = {r[1] for r in eco_rows if not r[6]}
    packages     = {r[4] for r in eco_rows}
    versions     = {(r[4], r[5]) for r in eco_rows}

    print(ECO_LABEL.get(eco, eco))
    print(summary_line('OSV files processed:',      osv_files))
    print(summary_line('Unique CVEs fixed:',         len(cves)))
    print(summary_line('Unique novel vulns fixed:',  len(novel)))
    print(summary_line('Unique packages affected:',  len(packages)))
    print(summary_line('Unique versions affected:',  len(versions)))
    print()
"
} | if [ -n "${_filename:-}" ]; then
    cat > "$_filename"
    echo "Saved to $_filename" >&2
else
    cat
fi
