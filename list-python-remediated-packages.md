# How Python remediated package listing works

## Python repository structure

The Lightwell Python repository exposes a **PyPI Simple API** (PEP 503), not
an Apache directory listing. There are three relevant endpoints:

| Endpoint | Returns | Purpose |
|---|---|---|
| `/lightwell/python/remediated/` | JSON `{"projects":N,"releases":N,"files":N}` | Pulp summary — not for crawling |
| `/lightwell/python/remediated/simple/` | HTML with package links | Index of all packages |
| `/lightwell/python/remediated/simple/{pkg}/` | HTML with file links + metadata | All files for a package |

The actual files are served from a different base:
```
https://packages.redhat.com/api/pulp-content/lightwell/python/remediated/
```

**Example — Simple index page for `pypdf2`:**

```html
<a href="https://packages.redhat.com/api/pulp-content/lightwell/python/remediated/pypdf2-3.0.1+rhlw.1.tar.gz#sha256=..."
   data-provenance="...">pypdf2-3.0.1+rhlw.1.tar.gz</a>
<a href="https://packages.redhat.com/api/pulp-content/lightwell/python/remediated/pypdf2-3.0.1+rhlw.1-1-py3-none-any.whl#sha256=..."
   data-provenance="...">pypdf2-3.0.1+rhlw.1-1-py3-none-any.whl</a>
```

### Expected artifact types

| File | Description |
|---|---|
| `*.whl` | Wheel — binary distribution, installable with `pip` |
| `*.tar.gz` | Source distribution (sdist) |

Provenance is linked via the `data-provenance` HTML attribute on each file link;
it is not a standalone file in the same listing.

---

## How the crawl works

The Python crawl uses the **PyPI Simple API**, not directory listing parsing.

### Step 1 — Fetch the Simple index

```
GET /lightwell/python/remediated/simple/
```

Parse all `<a href="...">` links to get the list of package names.

### Step 2 — Fetch per-package file list

For each package:
```
GET /lightwell/python/remediated/simple/{pkg}/
```

Parse `<a href="...">filename</a>` to get the list of files.

### Step 3 — Extract version from filename

| File type | Format | Version extraction |
|---|---|---|
| Wheel | `{name}-{version}(-{build})?-{python}-{abi}-{platform}.whl` | 2nd `-`-delimited segment |
| Source dist | `{name}-{version}.tar.gz` | Everything after first `-`, strip `.tar.gz` |

Example: `pypdf2-3.0.1+rhlw.1-1-py3-none-any.whl` → version `3.0.1+rhlw.1`

### Step 4 — Get timestamp

The Simple index does not include timestamps. A `HEAD` request is made to
the first file URL for each version to retrieve the `Last-Modified` HTTP header,
which is then used as the `added` timestamp.

> The Java repository at `/lightwell/java/remediated/.meta/prefixes.txt`
> provides a prefix catalog (37 entries). No equivalent exists for Python —
> the Simple index serves the same purpose.

---

## Manual verification steps

### 1 — Pulp summary (project/release/file counts)

```bash
curl -sL -u "$_user:$_pass" \
  'https://packages.redhat.com/lightwell/python/remediated/'
```

### 2 — Simple index (list of packages)

```bash
curl -sL -u "$_user:$_pass" \
  'https://packages.redhat.com/lightwell/python/remediated/simple/'
```

### 3 — File list for a specific package

```bash
curl -sL -u "$_user:$_pass" \
  'https://packages.redhat.com/lightwell/python/remediated/simple/pypdf2/'
```

### 4 — Get timestamp for a file (Last-Modified header)

```bash
curl -sIL -u "$_user:$_pass" \
  'https://packages.redhat.com/api/pulp-content/lightwell/python/remediated/pypdf2-3.0.1+rhlw.1.tar.gz' \
| grep -i last-modified
```

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
| Repository API | Apache directory listing | PyPI Simple API (PEP 503) |
| Package ID | `groupId:artifactId` | package name only |
| Version discovery | Directory containing `.pom` file | Filename parsed from Simple index |
| Timestamp source | Directory listing timestamp | `Last-Modified` HTTP header on file |
| Artifact types | jar, pom, sources.jar, test-sources.jar, cyclonedx.json, provenance.sigstore.json | whl, tar.gz |
| Entry point | `.meta/prefixes.txt` (37 entries) | `/simple/` index |
