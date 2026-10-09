# How Python remediated package listing works

## Python repository structure

The Lightwell Python repository at `https://packages.redhat.com/lightwell/python/remediated/`
follows a simple hierarchical layout. Every package lives at a path of the form:

```
{package-name}/{version}/{artifacts}
```

Unlike the Java Maven layout there is no `groupId` — the package name maps directly
to a single directory level.

**Example — `requests` version `2.31.0.rhlw-00001`:**

```
requests/
  2.31.0.rhlw-00001/
    requests-2.31.0.rhlw-00001-py3-none-any.whl
    requests-2.31.0.rhlw-00001.tar.gz
    requests-2.31.0.rhlw-00001.cyclonedx.json
    requests-2.31.0.rhlw-00001.provenance.sigstore.json
```

### Expected artifact types

| File | Description |
|---|---|
| `*.whl` | Wheel — binary distribution, installable with `pip` |
| `*.tar.gz` | Source distribution (sdist) |
| `*cyclonedx.json` | CycloneDX software bill of materials (SBOM) |
| `*.provenance.sigstore.json` | Sigstore provenance attestation |

---

## How the crawl works

### Entry point — prefix catalog

The repository exposes a prefix catalog at `.meta/prefixes.txt`:

```
https://packages.redhat.com/lightwell/python/remediated/.meta/prefixes.txt
```

Each non-comment line is a path prefix pointing directly at a package-name
directory. If the file is present the crawler uses it as seeds to avoid
fetching the root listing and all its entries one by one.

If no `prefixes.txt` is found, the crawler falls back to the root listing.

### Detection logic

A directory is treated as a **version directory** when it contains at least one
`.whl` or `.tar.gz` file. The package identity is derived from the path:

```
path segments:  [ "requests", "2.31.0.rhlw-00001" ]
                   ↑ last-2 = package name   ↑ last = version
package = segments[-2]   → "requests"
version = segments[-1]   → "2.31.0.rhlw-00001"
```

Because Python packages have no `groupId`, the package name is a single
segment (unlike Java where all segments except the last two are joined to form
the groupId).

### Parallelism

8 worker threads crawl directories concurrently. Recursion within each thread
is sequential to avoid nested thread-pool deadlocks.

---

## Manual verification steps

### 1 — Inspect the prefix catalog

```bash
curl -sL -u "$_user:$_pass" \
  'https://packages.redhat.com/lightwell/python/remediated/.meta/prefixes.txt'
```

### 2 — List available packages (root)

```bash
curl -sL -u "$_user:$_pass" \
  'https://packages.redhat.com/lightwell/python/remediated/'
```

### 3 — List versions for a package

```bash
curl -sL -u "$_user:$_pass" \
  'https://packages.redhat.com/lightwell/python/remediated/requests/'
```

### 4 — Inspect a version directory

```bash
curl -sL -u "$_user:$_pass" \
  'https://packages.redhat.com/lightwell/python/remediated/requests/2.31.0.rhlw-00001/'
```

Expected: `.whl`, `.tar.gz`, and optionally `cyclonedx.json` and
`provenance.sigstore.json` files.

---

## What is counted

| Metric | Definition |
|---|---|
| **Unique package** | One package name, regardless of how many versions exist |
| **Version** | One entry in a version directory containing `.whl` or `.tar.gz` files |

A package with two remediated versions counts as **1 package** and **2 versions**.

---

## Artifact completeness check

The `lightwell-menu.sh` option 6 (Check artifact completeness) checks four
artifact types for each Python package version:

| Column | Present (`X`) when… |
|---|---|
| `whl` | At least one `.whl` file exists in the version directory |
| `tar.gz` | At least one `.tar.gz` file exists |
| `cyclonedx.json` | A file containing `cyclonedx.json` in its name exists |
| `provenance.sigstore.json` | A file ending in `.provenance.sigstore.json` exists |

---

## Comparison with Java

| Aspect | Java | Python |
|---|---|---|
| Layout | Maven 2 (`groupId/artifactId/version/`) | Simple (`package-name/version/`) |
| Package ID | `groupId:artifactId` | package name only |
| Version detection | Directory contains `.pom` file | Directory contains `.whl` or `.tar.gz` |
| Artifact types | jar, pom, sources.jar, test-sources.jar, cyclonedx.json, provenance.sigstore.json | whl, tar.gz, cyclonedx.json, provenance.sigstore.json |
| Prefix catalog | Yes (`.meta/prefixes.txt`) | Yes (`.meta/prefixes.txt`) |
