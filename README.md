# Lightwell Scripts

| Script | Data source | Description |
|---|---|---|
| `count-advisories.sh` | GitHub (`lightwell-osv`) | Counts the total number of advisory JSON files in the public Lightwell OSV GitHub repository. |
| `count-remediations.sh` | GitHub (`lightwell-osv`) | Fetches all advisories from the GitHub repo and displays a table of remediations grouped by ecosystem (Maven / PyPI), showing the remediated version and CVEs fixed per package, plus a summary count of advisories, packages and CVEs. |
| `map-lightwell-osv-advisories.sh` | GitHub (`lightwell-osv`) | Produces a mapping table of every advisory in the GitHub repo: advisory filename, advisory ID, OSV schema version, ecosystem, package name, remediated version and CVEs fixed. Supports CSV export. |
| `map-lightwell-pulp-osv-advisories.sh` | Pulp (`packages.redhat.com`) | Same mapping as above but fetches from the authenticated Pulp OSV endpoints for both Java and Python (`/lightwell/osv/java/remediated/` and `/lightwell/osv/python/remediated/`). Includes a per-ecosystem summary (OSV files, CVEs, novel vulns, packages and versions). Requires `_user` / `_pass` credentials. |
| `list-java-packages.sh` | Pulp (`packages.redhat.com`) | Crawls the Lightwell Java Maven repository starting from the HTML root listing and enumerates all unique packages (`groupId:artifactId`) with their remediated versions. Requires credentials. |
| `list-java-packages-prefixes.sh` | Pulp (`packages.redhat.com`) | Same as `list-java-packages.sh` but uses `.meta/prefixes.txt` as the entry point instead of the root HTML listing, launching one crawl thread per prefix for faster enumeration. Use both scripts and compare totals to validate completeness. Requires credentials. |
