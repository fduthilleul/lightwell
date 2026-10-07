#!/usr/bin/env bash
# Count the number of advisory JSON files in the lightwell-osv GitHub repo.

set -euo pipefail

curl -s "https://api.github.com/repos/project-lightwell/lightwell-osv/contents/advisories" \
| jq 'length'
