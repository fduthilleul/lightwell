#!/usr/bin/env bash
# Enumerate unique packages (groupId:artifactId) and versions from the
# Lightwell Java Maven repository, using .meta/prefixes.txt as the entry point
# instead of crawling from the root HTML listing.

set -euo pipefail

export BASE_URL="https://packages.redhat.com/lightwell/java/remediated"

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
python3 -I - <<'PYEOF'
import os, sys, csv, urllib.request, urllib.error, html.parser, base64
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE_URL = os.environ["BASE_URL"].rstrip("/")
user     = os.environ["_user"]
pwd      = os.environ["_pass"]

creds = base64.b64encode(f"{user}:{pwd}".encode()).decode()
headers = {"Authorization": f"Basic {creds}"}

class LinkParser(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
    def handle_starttag(self, tag, attrs):
        if tag == "a":
            for k, v in attrs:
                if k == "href" and v not in ("../", "./", "/") and not v.startswith("?"):
                    self.links.append(v.lstrip("./"))

def fetch_text(url):
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.read().decode(errors="replace")
    except urllib.error.HTTPError:
        return ""

def fetch_links(url):
    body = fetch_text(url)
    p = LinkParser()
    p.feed(body)
    return p.links

def is_file(name):
    return "." in name and not name.endswith("/")

def crawl(path):
    """Return list of (groupId:artifactId, version) tuples found under path."""
    url = f"{BASE_URL}/{path.lstrip('/')}/"
    links = fetch_links(url)
    dirs  = [l for l in links if l.endswith("/")]
    files = [l for l in links if is_file(l) and (l.endswith(".pom") or l.endswith(".jar"))]

    if files:
        # Version directory: last segment = version, second-to-last = artifactId
        parts = path.strip("/").split("/")
        if len(parts) >= 2:
            version    = parts[-1]
            artifact   = parts[-2]
            group_id   = ".".join(parts[:-2])
            return [(f"{group_id}:{artifact}", version)]
        return []

    results = []
    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(crawl, path.rstrip("/") + "/" + d): d for d in dirs}
        for fut in as_completed(futures):
            results.extend(fut.result())
    return results

# Load prefixes from .meta/prefixes.txt
sys.stderr.write("Loading prefixes from .meta/prefixes.txt...\n")
prefixes_url = f"{BASE_URL}/.meta/prefixes.txt"
prefixes_text = fetch_text(prefixes_url)
prefixes = [
    line.strip().lstrip("/")
    for line in prefixes_text.splitlines()
    if line.strip() and not line.startswith("#")
]
sys.stderr.write(f"Found {len(prefixes)} prefixes. Crawling...\n")

# Crawl each prefix in parallel at the top level
entries = []
with ThreadPoolExecutor(max_workers=len(prefixes)) as ex:
    futures = {ex.submit(crawl, p): p for p in prefixes}
    for fut in as_completed(futures):
        entries.extend(fut.result())

# Aggregate: package -> set of versions
from collections import defaultdict
pkg_versions = defaultdict(set)
for pkg, ver in entries:
    pkg_versions[pkg].add(ver)

output_csv = os.environ.get("OUTPUT_CSV", "0") == "1"
rows = sorted((pkg, ", ".join(sorted(vers))) for pkg, vers in pkg_versions.items())

if output_csv:
    writer = csv.writer(sys.stdout)
    writer.writerow(["Package", "Remediated versions"])
    for r in rows:
        writer.writerow(r)
else:
    col0 = max(len("Package"),             max(len(r[0]) for r in rows))
    col1 = max(len("Remediated versions"),  max(len(r[1]) for r in rows))

    def row(a, b):
        return f"  {a:<{col0}}  {b}"

    print(row("Package", "Remediated versions"))
    print(row("-"*col0, "-"*col1))
    for r in rows:
        print(row(*r))

    print()
    total_vers = sum(len(vers) for vers in pkg_versions.values())
    print(f"  Total: {len(pkg_versions)} unique package(s), {total_vers} version(s)")
PYEOF
} | if [ -n "${_filename:-}" ]; then
    cat > "$_filename"
    echo "Saved to $_filename" >&2
else
    cat
fi
