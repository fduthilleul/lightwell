#!/usr/bin/env bash
# Count Lightwell remediations per ecosystem family from the lightwell-osv GitHub repo.
# Outputs one markdown table per ecosystem family.

set -euo pipefail

curl -s "https://api.github.com/repos/project-lightwell/lightwell-osv/contents/advisories" \
| jq -r '.[].download_url' \
| while read -r url; do
    curl -s "$url" | jq -r \
      '.id as $id
       | (.affected | map(select(.package.ecosystem | startswith("Red Hat Lightwell:"))))
           as $rhlw_entries
       | (if ($rhlw_entries | length) > 0 then $rhlw_entries else .affected end)[]
       | [
           $id,
           .package.ecosystem,
           .package.name,
           (
             ([(.ranges // [])[] | .events[]? | select(has("fixed")) | .fixed][0])
             // .database_specific?.lightwell?.remediated_version
             // ""
           )
         ]
       | @tsv'
  done \
| python3 -I -c "
import sys
from collections import defaultdict

data = defaultdict(lambda: defaultdict(list))

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    parts = line.split('\t', 3)
    if len(parts) < 3:
        continue
    _adv_id, eco, pkg = parts[0], parts[1], parts[2]
    ver = parts[3] if len(parts) > 3 else ''
    family = eco.removeprefix('Red Hat Lightwell:')
    data[family][pkg].append(ver)

col1 = max(len('Ecosystem'), max(len(f) for f in data))
col2 = max(len('Package'), max(len(p) for pkgs in data.values() for p in pkgs))
col3 = max(len('Version'), max(len(v) for pkgs in data.values() for vers in pkgs.values() for v in vers))

def row(a, b, c):
    return f'  {a:<{col1}}  {b:<{col2}}  {c:<{col3}}'

print(row('Ecosystem', 'Package', 'Version'))
print(row('-' * col1, '-' * col2, '-' * col3))
for family in sorted(data):
    pkgs = data[family]
    first_pkg = True
    for pkg in sorted(pkgs):
        for i, ver in enumerate(sorted(pkgs[pkg])):
            eco_cell = family if first_pkg and i == 0 else ''
            pkg_cell = pkg if i == 0 else ''
            print(row(eco_cell, pkg_cell, ver))
        first_pkg = False
    print()

print()
print('Summary')
print('-------')
total_pkgs = 0
total_remediations = 0
for family in sorted(data):
    pkgs = data[family]
    n_pkgs = len(pkgs)
    n_rem = sum(len(v) for v in pkgs.values())
    total_pkgs += n_pkgs
    total_remediations += n_rem
    print(f'  {family}: {n_pkgs} package(s), {n_rem} remediation(s)')
print(f'  Total: {total_pkgs} package(s), {total_remediations} remediation(s)')
"
