#!/usr/bin/env bash
# For each remediated Java package+version in the Lightwell Maven repo,
# check the presence of: .jar, .pom, sources.jar, test-sources.jar,
# cyclonedx.json, .provenance.sigstore.json
# Missing files are marked with X in the corresponding column.

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

creds   = base64.b64encode(f"{user}:{pwd}".encode()).decode()
headers = {"Authorization": f"Basic {creds}"}

CHECKS = [
    ("jar",                      lambda files: any(f.endswith(".jar") and not f.endswith("-sources.jar") and not f.endswith("-test-sources.jar") for f in files)),
    ("pom",                      lambda files: any(f.endswith(".pom") for f in files)),
    ("sources.jar",              lambda files: any(f.endswith("-sources.jar") for f in files)),
    ("test-sources.jar",         lambda files: any(f.endswith("-test-sources.jar") for f in files)),
    ("cyclonedx.json",           lambda files: any("cyclonedx.json" in f for f in files)),
    ("provenance.sigstore.json", lambda files: any(f.endswith(".provenance.sigstore.json") for f in files)),
]

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
    p = LinkParser()
    p.feed(fetch_text(url))
    return p.links

def is_file(name):
    return not name.endswith("/") and "." in name

def crawl(path):
    """Return list of result rows found under path."""
    url   = f"{BASE_URL}/{path.lstrip('/')}/"
    links = fetch_links(url)
    dirs  = [l for l in links if l.endswith("/") and not l.startswith(".")]
    files = [l for l in links if is_file(l)]

    # Version directory: contains a .pom file
    if any(f.endswith(".pom") for f in files):
        parts = path.strip("/").split("/")
        if len(parts) < 2:
            return []
        version  = parts[-1]
        artifact = parts[-2]
        group_id = ".".join(parts[:-2])
        pkg      = f"{group_id}:{artifact}"
        presence = ["X" if chk(files) else "-" for _, chk in CHECKS]
        return [(pkg, version) + tuple(presence)]

    results = []
    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(crawl, path.rstrip("/") + "/" + d): d for d in dirs}
        for fut in as_completed(futures):
            results.extend(fut.result())
    return results

# Load prefixes
sys.stderr.write("Loading prefixes...\n")
prefixes_text = fetch_text(f"{BASE_URL}/.meta/prefixes.txt")
prefixes = [
    line.strip().lstrip("/")
    for line in prefixes_text.splitlines()
    if line.strip() and not line.startswith("#")
]
sys.stderr.write(f"Found {len(prefixes)} prefixes. Crawling...\n")

rows = []
with ThreadPoolExecutor(max_workers=len(prefixes)) as ex:
    futures = {ex.submit(crawl, p): p for p in prefixes}
    for fut in as_completed(futures):
        rows.extend(fut.result())

rows.sort(key=lambda x: (x[0], x[1]))

HEADERS = ["Package", "Remediated version"] + [c for c, _ in CHECKS]

output_csv = os.environ.get("OUTPUT_CSV", "0") == "1"

if not rows:
    print("No data retrieved.", file=sys.stderr)
    sys.exit(1)

if output_csv:
    writer = csv.writer(sys.stdout)
    writer.writerow(HEADERS)
    for r in rows:
        writer.writerow(r)
else:
    check_names = [c for c, _ in CHECKS]
    col0 = max(len("Package"),            max(len(r[0]) for r in rows))
    col1 = max(len("Remediated version"), max(len(r[1]) for r in rows))
    # Check columns: width = header length (values are "" or "X")
    col_w = [max(len(name), 1) for name in check_names]

    def fmt_row(pkg, ver, *vals):
        line = f"  {pkg:<{col0}}  {ver:<{col1}}"
        for v, w in zip(vals, col_w):
            line += f"  {v:^{w}}"
        return line

    # Header
    header = f"  {'Package':<{col0}}  {'Remediated version':<{col1}}"
    for name, w in zip(check_names, col_w):
        header += f"  {name:^{w}}"
    print(header)

    sep = f"  {'-'*col0}  {'-'*col1}"
    for w in col_w:
        sep += f"  {'-'*w}"
    print(sep)

    for r in rows:
        print(fmt_row(*r))

    print()
    missing = sum(1 for r in rows for v in r[2:] if v == "-")
    print(f"  Total: {len(rows)} package version(s), {missing} missing artifact(s)")
PYEOF
} | if [ -n "${_filename:-}" ]; then
    cat > "$_filename"
    echo "Saved to $_filename" >&2
else
    cat
fi
