# How list-java-remediated-packages.sh works

## Maven repository structure

The Lightwell Java repository at `https://packages.redhat.com/lightwell/java/remediated/`
is a standard Maven 2 layout. Every artifact lives at a path of the form:

```
{groupId — dots replaced by /}/{artifactId}/{version}/{artifactId}-{version}.jar
                                                       {artifactId}-{version}.pom
                                                       ...
```

**Example — `ch.qos.logback:logback-classic` version `1.2.12.rhlw-00005`:**

```
ch/
  qos/
    logback/
      logback-classic/          ← artifactId directory
        1.2.12.rhlw-00005/      ← version directory
          logback-classic-1.2.12.rhlw-00005.jar
          logback-classic-1.2.12.rhlw-00005.pom
```

**Example — `commons-io:commons-io` (no sub-group):**

```
commons-io/
  commons-io/                   ← artifactId directory
    2.11.0.rhlw-00003/          ← version directory
      commons-io-2.11.0.rhlw-00003.jar
      commons-io-2.11.0.rhlw-00003.pom
```

---

## How the script crawls the tree

1. **Start at the root** — fetches the HTML directory listing of the base URL.
2. **Recurse into every subdirectory** — follows all `href` links that end with `/`
   (skipping `../` and query strings).
3. **Detect a version directory** — when a directory contains at least one `.jar`
   or `.pom` file, the script treats it as a version directory. It does **not**
   try to guess version directories by name pattern.
4. **Derive the package identity** — once a version directory is found, the script
   splits its path into segments:

   ```
   path segments:  [ "ch", "qos", "logback", "logback-classic", "1.2.12.rhlw-00005" ]
                     ↑ everything except last two   ↑ last-2 = artifactId  ↑ last = version
   groupId  = join(segments[:-2], ".") → "ch.qos.logback"
   artifactId = segments[-2]           → "logback-classic"
   version    = segments[-1]           → "1.2.12.rhlw-00005"
   ```

5. **Parallelism** — 8 threads fetch directory listings concurrently to keep the
   crawl fast despite the depth of the tree.

---

## Manual verification steps

To check that the approach is correct you can spot-check any package:

### 1 — Verify a known package path

```bash
# Should return a directory listing with version subdirectories
curl -sL -u "$_user:$_pass" \
  'https://packages.redhat.com/lightwell/java/remediated/ch/qos/logback/logback-classic/'
```

### 2 — Verify a version directory contains .jar/.pom files

```bash
curl -sL -u "$_user:$_pass" \
  'https://packages.redhat.com/lightwell/java/remediated/ch/qos/logback/logback-classic/1.2.12.rhlw-00005/'
```

Expected: `.jar`, `.pom`, and optionally `.sha1`/`.md5` checksum files.

### 3 — Verify a flat group (no sub-group)

```bash
# groupId = "commons-io", artifactId = "commons-io"
curl -sL -u "$_user:$_pass" \
  'https://packages.redhat.com/lightwell/java/remediated/commons-io/'
```

### 4 — Count top-level group directories

```bash
curl -sL -u "$_user:$_pass" \
  'https://packages.redhat.com/lightwell/java/remediated/' \
| grep -oP 'href="\./[^"]+/"' | grep -v '\.meta'
```

These are the root group-ID path segments (`ch/`, `com/`, `org/`, etc.).

---

## What the script counts

| Metric | Definition |
|---|---|
| **Unique package** | One `groupId:artifactId` pair, regardless of how many versions exist |
| **Version** | One entry in a version directory that contains `.jar`/`.pom` files |

A package with three remediated versions (e.g. `1.x`, `2.x`, `3.x`) counts as
**1 package** and **3 versions**.

---

## Known edge cases

- **`.meta/` directory** — skipped automatically because it contains no `.jar`/`.pom` files at the leaf level.
- **Flat groupIds** (e.g. `commons-io`) — handled correctly; the path split still yields `groupId:artifactId`.
- **Deep groupIds** (e.g. `org.springframework.security`) — handled correctly; all segments except the last two are joined with `.` to form the groupId.
