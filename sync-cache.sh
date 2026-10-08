#!/usr/bin/env bash
# Build / refresh the local Lightwell cache.
# Cache location: ~/.lightwell/cache/
#
# Sources cached:
#   1) GitHub OSV advisories  → github-advisories/*.json
#   2) Pulp OSV advisories    → pulp-java-advisories/*.json
#                               pulp-python-advisories/*.json
#   3) Maven repository index → maven-index.json  (crawl results)

set -euo pipefail

CACHE_DIR="${LIGHTWELL_CACHE:-$HOME/.lightwell/cache}"
GITHUB_DIR="$CACHE_DIR/github-advisories"
PULP_JAVA_DIR="$CACHE_DIR/pulp-java-advisories"
PULP_PYTHON_DIR="$CACHE_DIR/pulp-python-advisories"
MAVEN_INDEX="$CACHE_DIR/maven-index.json"
TS_FILE="$CACHE_DIR/timestamps.json"

GITHUB_API="https://api.github.com/repos/project-lightwell/lightwell-osv/contents/advisories"
PULP_BASE="https://packages.redhat.com/api/pulp-content/lightwell/osv"
MAVEN_BASE="https://packages.redhat.com/lightwell/java/remediated"

# ── Helpers ──────────────────────────────────────────────────────────────────

ts_now() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

save_ts() {
  local key="$1" val; val=$(ts_now)
  python3 -I -c "
import json, sys
ts = {}
try:
    ts = json.load(open('$TS_FILE'))
except Exception:
    pass
ts['$key'] = '$val'
json.dump(ts, open('$TS_FILE', 'w'), indent=2)
print('  Timestamp saved:', '$val')
"
}

read_ts() {
  local key="$1"
  python3 -I -c "
import json, sys
try:
    ts = json.load(open('$TS_FILE'))
    print(ts.get('$key', 'never'))
except Exception:
    print('never')
" 2>/dev/null
}

# ── Credentials (Pulp only) ───────────────────────────────────────────────────

ensure_creds() {
  if [[ -z "${_user:-}" ]]; then read -rp  "Username: " _user; fi
  if [[ -z "${_pass:-}" ]]; then read -rsp "Password: " _pass; echo; fi
  export _user _pass
}

# ── Sync functions ────────────────────────────────────────────────────────────

sync_github() {
  echo "Syncing GitHub OSV advisories..."
  mkdir -p "$GITHUB_DIR"
  local count=0
  curl -s "$GITHUB_API" | jq -r '.[] | [.name, .download_url] | @tsv' \
  | while IFS=$'\t' read -r name url; do
      curl -s "$url" -o "$GITHUB_DIR/$name"
      count=$((count + 1))
      printf "\r  Downloaded %d files..." "$count"
    done
  echo ""
  count=$(ls "$GITHUB_DIR"/*.json 2>/dev/null | wc -l)
  echo "  Done: $count files cached."
  save_ts "github"
}

sync_pulp_osv() {
  ensure_creds
  echo "Syncing Pulp OSV advisories (Java + Python)..."
  for eco in java python; do
    local dir
    dir="$CACHE_DIR/pulp-${eco}-advisories"
    mkdir -p "$dir"
    local base_url="$PULP_BASE/$eco/remediated"
    local count=0
    curl -sL -u "$_user:$_pass" "$base_url/" \
    | grep -oP 'x_RHLW-[^"]+\.json' | sort -u \
    | while read -r f; do
        curl -sL -u "$_user:$_pass" "$base_url/$f" -o "$dir/$f"
        count=$((count + 1))
        printf "\r  [%s] Downloaded %d files..." "$eco" "$count"
      done
    echo ""
    count=$(ls "$dir"/*.json 2>/dev/null | wc -l)
    echo "  [$eco] Done: $count files cached."
  done
  save_ts "pulp_osv"
}

sync_maven() {
  ensure_creds
  echo "Syncing Maven repository index (this may take a few minutes)..."
  export _user _pass MAVEN_BASE MAVEN_INDEX
  python3 -I - <<'PYEOF'
import os, sys, re, json, urllib.request, urllib.error, base64, threading, queue
from datetime import datetime, timezone

MAVEN_BASE  = os.environ["MAVEN_BASE"].rstrip("/")
MAVEN_INDEX = os.environ["MAVEN_INDEX"]
user        = os.environ["_user"]
pwd         = os.environ["_pass"]

creds   = base64.b64encode(f"{user}:{pwd}".encode()).decode()
headers = {"Authorization": f"Basic {creds}"}

ENTRY_RE = re.compile(
    r'href="\.?/?([^"?][^"]*)">[^<]*</a>\s+(\d{2}-[A-Za-z]{3}-\d{4} \d{2}:\d{2})'
)
ARTIFACT_CHECKS = [
    ("jar",                      lambda fs: any(f.endswith(".jar") and "-sources" not in f and "-test-sources" not in f for f in fs)),
    ("pom",                      lambda fs: any(f.endswith(".pom") for f in fs)),
    ("sources_jar",              lambda fs: any(f.endswith("-sources.jar") for f in fs)),
    ("test_sources_jar",         lambda fs: any(f.endswith("-test-sources.jar") for f in fs)),
    ("cyclonedx_json",           lambda fs: any("cyclonedx.json" in f for f in fs)),
    ("provenance_sigstore_json", lambda fs: any(f.endswith(".provenance.sigstore.json") for f in fs)),
]

def fetch_text(url):
    req = urllib.request.Request(url, headers=headers)
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.read().decode(errors="replace")
        except Exception:
            if attempt == 2: return ""
            import time; time.sleep(1)
    return ""

def fetch_entries(url):
    body = fetch_text(url)
    return [(m.group(1).lstrip("./"), m.group(2)) for m in ENTRY_RE.finditer(body)]

# Load prefixes
prefixes_text = fetch_text(f"{MAVEN_BASE}/.meta/prefixes.txt")
prefixes = [l.strip().lstrip("/") for l in prefixes_text.splitlines()
            if l.strip() and not l.startswith("#")]
sys.stderr.write(f"  Found {len(prefixes)} prefixes\n")

work_q  = queue.Queue()
results = []
lock    = threading.Lock()
counter = [0]

for p in prefixes:
    work_q.put((p, None))

def worker():
    while True:
        try:
            path, entry_ts = work_q.get(timeout=10)
        except queue.Empty:
            break
        try:
            url     = f"{MAVEN_BASE}/{path.lstrip('/')}/"
            entries = fetch_entries(url)
            dirs    = [(n, ts) for n, ts in entries if n.endswith("/") and not n.startswith(".")]
            files   = [n for n, _ in entries if not n.endswith("/")]

            if any(f.endswith(".pom") for f in files):
                parts = path.strip("/").split("/")
                if len(parts) >= 2:
                    version  = parts[-1]
                    artifact = parts[-2]
                    group_id = ".".join(parts[:-2])
                    pkg      = f"{group_id}:{artifact}" if group_id else artifact
                    art      = {k: chk(files) for k, chk in ARTIFACT_CHECKS}
                    with lock:
                        results.append({"ecosystem": "java", "pkg": pkg,
                                        "version": version, "added": entry_ts or "",
                                        **art})
                        counter[0] += 1
                        if counter[0] % 10 == 0:
                            sys.stderr.write(f"\r  Indexed {counter[0]} versions...")
            else:
                for dirname, ts in dirs:
                    work_q.put((path.rstrip("/") + "/" + dirname.rstrip("/"), ts))
        finally:
            work_q.task_done()

threads = [threading.Thread(target=worker, daemon=True) for _ in range(8)]
for t in threads: t.start()
work_q.join()

sys.stderr.write(f"\r  Indexed {len(results)} versions.      \n")

output = {
    "synced_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "entries": sorted(results, key=lambda x: (x["pkg"], x["version"]))
}
with open(MAVEN_INDEX, "w") as f:
    json.dump(output, f, indent=2)
print(f"  Maven index saved: {len(results)} versions across {len({e['pkg'] for e in results})} packages.")
PYEOF
  save_ts "maven"
}

# ── Menu ──────────────────────────────────────────────────────────────────────

echo ""
echo "Lightwell Cache Sync"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Cache location: $CACHE_DIR"
echo ""
echo "  GitHub OSV last sync : $(read_ts github)"
echo "  Pulp OSV  last sync  : $(read_ts pulp_osv)"
echo "  Maven index last sync: $(read_ts maven)"
echo ""
echo "What would you like to sync?"
echo "  1) GitHub OSV advisories"
echo "  2) Pulp OSV advisories (Java + Python)"
echo "  3) Maven repository index (slow — crawls ~3,400 dirs)"
echo "  4) All"
echo "  0) Cancel"
echo ""
read -rp "Choice: " _choice

case "$_choice" in
  1) sync_github ;;
  2) sync_pulp_osv ;;
  3) sync_maven ;;
  4) sync_github; sync_pulp_osv; sync_maven ;;
  0) echo "Cancelled." ;;
  *) echo "Invalid choice." >&2; exit 1 ;;
esac

echo ""
echo "Done. Run ./lightwell-menu.sh to query the cache."
