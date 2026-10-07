#!/usr/bin/env bash
# Count Lightwell remediations per ecosystem family from the lightwell-osv GitHub repo.
# One advisory file = one remediation. Shows remediated version and CVEs fixed per package.

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
| jq -r '.[].download_url' \
| while read -r url; do
    curl -s "$url" | jq -r \
      '[.upstream[]? | select(startswith("CVE-"))] as $cves
       | .id as $id
       | .affected[]
       | [
           $id,
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
import sys
from collections import defaultdict

# data[family][pkg] = [(adv_id, version, [cves])]
data = defaultdict(lambda: defaultdict(list))

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    parts = line.split('\t', 4)
    if len(parts) < 3:
        continue
    adv_id, eco, pkg = parts[0], parts[1], parts[2]
    ver   = parts[3] if len(parts) > 3 else ''
    cves  = [c for c in parts[4].split(',') if c] if len(parts) > 4 else []
    family = eco.removeprefix('Red Hat Lightwell:')
    data[family][pkg].append((adv_id, ver, cves))

import os, csv as csvmod

output_csv = os.environ.get('OUTPUT_CSV', '0') == '1'

if output_csv:
    writer = csvmod.writer(sys.stdout)
    writer.writerow(['Ecosystem', 'Package', 'Version', 'CVEs fixed'])
    for family in sorted(data):
        for pkg in sorted(data[family]):
            for adv_id, ver, cves in sorted(data[family][pkg], key=lambda x: x[1]):
                writer.writerow([family, pkg, ver, ', '.join(cves)])
else:
    all_cve_strs = [', '.join(cves) for pkgs in data.values() for entries in pkgs.values() for _, _, cves in entries]
    col1 = max(len('Ecosystem'), max(len(f) for f in data))
    col2 = max(len('Package'),   max(len(p) for pkgs in data.values() for p in pkgs))
    col3 = max(len('Version'),   max((len(ver) for pkgs in data.values() for entries in pkgs.values() for _, ver, _ in entries), default=0))
    col4 = max(len('CVEs fixed'), max((len(s) for s in all_cve_strs), default=0))

    def row(a, b, c, d):
        return f'  {a:<{col1}}  {b:<{col2}}  {c:<{col3}}  {d}'

    print(row('Ecosystem', 'Package', 'Version', 'CVEs fixed'))
    print(row('-' * col1, '-' * col2, '-' * col3, '-' * col4))

    for family in sorted(data):
        pkgs = data[family]
        first_pkg = True
        for pkg in sorted(pkgs):
            entries = sorted(pkgs[pkg], key=lambda x: x[1])
            for i, (adv_id, ver, cves) in enumerate(entries):
                eco_cell = family if first_pkg and i == 0 else ''
                pkg_cell = pkg if i == 0 else ''
                print(row(eco_cell, pkg_cell, ver, ', '.join(cves)))
            first_pkg = False
        print()

print()
print('Summary')
print('-------')
total_advisories = set()
total_packages   = 0
total_cves       = set()
for family in sorted(data):
    pkgs         = data[family]
    fam_adv      = set(adv_id for entries in pkgs.values() for adv_id, _, _ in entries)
    fam_cves     = set(cve for entries in pkgs.values() for _, _, cves in entries for cve in cves)
    total_advisories.update(fam_adv)
    total_packages  += len(pkgs)
    total_cves.update(fam_cves)
    print(f'  {family}: {len(fam_adv)} advisory/advisories, {len(pkgs)} package(s), {len(fam_cves)} CVE(s) fixed')
print(f'  Total: {len(total_advisories)} advisory/advisories, {total_packages} package(s), {len(total_cves)} CVE(s) fixed')
"
} | if [ -n "$_filename" ]; then
    cat > "$_filename"
    echo "Saved to $_filename" >&2
else
    cat
fi
