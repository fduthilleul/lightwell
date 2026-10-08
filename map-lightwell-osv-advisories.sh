#!/usr/bin/env bash
# Map advisory file names to ecosystem, package and remediated version
# from the lightwell-osv GitHub repo (new RHLW-2026-* naming scheme).

set -euo pipefail

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
curl -s "https://api.github.com/repos/project-lightwell/lightwell-osv/contents/advisories" \
| jq -r '.[] | [.name, .download_url] | @tsv' \
| while IFS=$'\t' read -r filename url; do
    curl -s "$url" | jq -r \
      --arg fname "$filename" \
      '[.upstream[]? | select(startswith("CVE-"))] as $cves
       | .id as $id
       | .schema_version as $schema
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

if output_csv:
    writer = csvmod.writer(sys.stdout)
    writer.writerow(['File', 'Advisory ID', 'OSV Schema Version', 'Ecosystem', 'Package', 'Remediated version', 'CVEs'])
    for r in sorted(rows, key=lambda x: (x[3], x[4], x[5])):
        writer.writerow(r)
else:
    col0 = max(len('File'),                max(len(r[0]) for r in rows))
    col1 = max(len('Advisory ID'),         max(len(r[1]) for r in rows))
    col2 = max(len('OSV Schema Version'),  max(len(r[2]) for r in rows))
    col3 = max(len('Ecosystem'),           max(len(r[3]) for r in rows))
    col4 = max(len('Package'),             max(len(r[4]) for r in rows))
    col5 = max(len('Remediated version'),  max(len(r[5]) for r in rows))
    col6 = max(len('CVEs'),                max(len(r[6]) for r in rows))

    def row(a, b, c, d, e, f, g=''):
        return f'  {a:<{col0}}  {b:<{col1}}  {c:<{col2}}  {d:<{col3}}  {e:<{col4}}  {f:<{col5}}  {g}'

    print(row('File', 'Advisory ID', 'OSV Schema Version', 'Ecosystem', 'Package', 'Remediated version', 'CVEs'))
    print(row('-'*col0, '-'*col1, '-'*col2, '-'*col3, '-'*col4, '-'*col5, '-'*col6))
    for r in sorted(rows, key=lambda x: (x[3], x[4], x[5])):
        print(row(*r))

    print()
    print(f'Total: {len(rows)} advisory/package mapping(s)')
"
} | if [ -n "${_filename:-}" ]; then
    cat > "$_filename"
    echo "Saved to $_filename" >&2
else
    cat
fi
