# scan-dockers-trivy — a wrapper around Trivy for scanning Docker images and generating a report

This repository contains a Python script `trivy-scanner.py` that **mass-scans Docker images using Trivy** and saves a **compact JSON report** with findings grouped by component type and severity.

Use cases:
- **Remote**: scan *remote* images from a registry (list in `input_images.txt`)
- **Local**: build images from *local* `Dockerfile` and scan them (list in `input_images_files.txt`)
- **Both**: run both modes sequentially

- [Документация на русском](docs/README_RU.md)

---

## What the script does

### 1) Reads targets from input files
- `input_images.txt` — list of image references (preferably pinned by digest `@sha256:...`)
- `input_images_files.txt` — list of paths to Dockerfiles to **build** and then **scan**

Both files define a severity filter threshold: `severity=1..5`.

### 2) Prepares Trivy DB once, safely for parallel runs
Trivy does not like parallel DB updates in the same `--cache-dir`. The script solves this by:
- creating a local cache `./.trivy_cache`
- under a file lock, downloading the vulnerability DB (and Java DB when possible) **once**
- then running scans with `--skip-db-update` (and `--skip-java-db-update` if Java DB is available)

If DB corruption / incomplete download is detected during execution, the script runs `repair` (deletes `db/` and `java-db/` inside the cache and re-downloads), then retries the scan once.

> ⚠️ File locking is implemented via `fcntl` and fully works on Linux. On Windows, inter-process locking may be absent.

### 3) Runs scans in parallel and prints progress
- Progress and summaries are printed to **stderr**
- **stdout** prints **only the final JSON filename** (pipeline-friendly)

### 4) Produces the final JSON report
The result is saved next to the script:
- `advanced_scan_results_remote_YYYYmmdd_HHMMSS.json`
- `advanced_scan_results_local_YYYYmmdd_HHMMSS.json`
- `advanced_scan_results_both_YYYYmmdd_HHMMSS.json`

---

## Requirements

Minimum:
- **Python 3.8+** (no dependencies — standard library only)
- **Trivy** available in `PATH` (`trivy version` must work)
- For **local** mode additionally **Docker** is required:
  - access to Docker daemon (usually `/var/run/docker.sock`)
  - permissions to build and remove images (`docker build`, `docker rmi`)

Recommended:
- Linux (because of `fcntl` locking and typical Docker/Trivy environment)

---

## Project structure

- `trivy-scanner.py` — main script
- `input_images.txt` — remote images list + `severity=...`
- `input_images_files.txt` — Dockerfile paths list + `severity=...`
- `.trivy_cache/` — auto-created (Trivy cache + DB)
- `Docker_files/` — auxiliary directory (not mandatory for the current script)

---

## Quick start

### 1) Prepare input files

#### Remote: `input_images.txt`
Example:
```txt
# Severity level: 1=UNKNOWN+, 2=LOW+, 3=MEDIUM+, 4=HIGH+, 5=CRITICAL
severity=4

# Docker images to scan (better pin by digest)
ghcr.io/grafana/k6-operator:runner-v1.2.0@sha256:...
ghcr.io/grafana/k6-operator:starter-v1.2.0@sha256:...
```

#### Local: `input_images_files.txt`
Example:
```txt
# Severity level: 1=UNKNOWN+, 2=LOW+, 3=MEDIUM+, 4=HIGH+, 5=CRITICAL
severity=4

# Paths to Dockerfiles (prefer absolute, or relative to the run directory)
./path/to/Dockerfile
/home/user/projects/app/Dockerfile
```

---

### 2) Run

Interactive menu (if `--mode` is not provided):
```bash
python3 trivy-scanner.py
```

Run a specific mode directly:

**Remote:**
```bash
python3 trivy-scanner.py --mode remote
```

**Local:**
```bash
python3 trivy-scanner.py --mode local
```

**Both (remote + local):**
```bash
python3 trivy-scanner.py --mode both
```

---

## CLI options

```bash
python3 trivy-scanner.py --help
```

Key flags:
- `--mode {remote,local,both}` — run mode (if omitted — interactive menu)
- `--jobs-remote N` — remote scan concurrency (default: `2`)
- `--jobs-local N` — local mode concurrency (build+scan) (default: `1`)
- `--trivy-timeout 10m` — Trivy timeout (default: `10m`)

---

## Severity filtering logic

Input files define `severity=1..5`:

| severity | included in report |
|---:|---|
| 1 | `UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL` |
| 2 | `LOW, MEDIUM, HIGH, CRITICAL` |
| 3 | `MEDIUM, HIGH, CRITICAL` |
| 4 | `HIGH, CRITICAL` |
| 5 | `CRITICAL` |

---

## What goes into the report

The script reads Trivy-generated JSON and collects:
- **Vulnerabilities** (package vulnerabilities)
- **Secrets** (secrets) if Trivy returns them in your mode/version

Then it groups by:
1) **component type**, derived from `Class/Type/Target` fields (e.g., `Debian-package`, `Go-package`, `NodeJS-package`, `Java-package`, `Secret`, …)
2) **Severity** (`CRITICAL`, `HIGH`, …)

---

## Final JSON format (top-level schema)

The final file is a **JSON array of objects**, one per scanned target.

### Remote element
```json
{
  "image": "registry.example.com/app@sha256:...",
  "scan_timestamp": "2026-02-17T12:34:56.789",
  "severity_level": 4,
  "included_severities": ["HIGH","CRITICAL"],
  "scan_type": "remote",

  "Debian-package": {
    "CRITICAL": [
      {
        "vuln_id": "CVE-2025-XXXX",
        "installed_vers": "1.2.3",
        "fixed": "1.2.4",
        "library": "libssl3",
        "type_detail": "debian",
        "class_detail": "os-pkgs",
        "target": "Debian 12.0 (bookworm)",
        "type": "vulnerability",
        "title": "...",
        "description": "...",
        "primaryurl": "..."
      }
    ]
  },

  "Secret": {
    "HIGH": [
      {
        "secret_id": "xxx",
        "category": "xxx",
        "title": "xxx",
        "target": "/path/in/layer",
        "start_line": 10,
        "end_line": 10,
        "match": "....",
        "type_detail": "filesystem",
        "class_detail": "secret",
        "type": "secret"
      }
    ]
  }
}
```

### Local element
Difference: `dockerfile` is present and the image name is temporary:
```json
{
  "dockerfile": "/abs/path/to/Dockerfile",
  "image": "local_scan_project_YYYYmmdd_HHMMSS_ffffff:latest",
  "scan_type": "local",
  "...": "..."
}
```

---

## Local mode specifics (Dockerfile)

In local mode, for each Dockerfile:
1) determine Dockerfile directory (used as build context)
2) run `docker build -q -f <Dockerfile> -t <temp_image> .`
3) scan the built image with Trivy
4) remove the image `docker rmi -f <temp_image>`

If build fails, the script adds a result object with `error`.

---

## Common issues and quick fixes

### 1) No access to Docker daemon (local mode)
Symptoms: `permission denied`, `cannot connect to the Docker daemon`, `dial unix /var/run/docker.sock`.

Fix:
- add the user to the `docker` group and re-login, or
- run the script as root, or
- use sudo where needed.

The script **automatically** retries Trivy scan with `sudo` if the error looks like a permissions issue.

### 2) Trivy DB issues (corruption/incomplete download)
The script attempts repair automatically, but if you want to do it manually:
```bash
trivy clean --vuln-db --java-db
# or:
rm -rf ./.trivy_cache/db ./.trivy_cache/java-db
```

### 3) Old Trivy version does not support flags
The script falls back (re-runs without unsupported flags) if it sees `unknown flag` for:
- `--no-progress`
- `--quiet`
- `--timeout`
- `--skip-db-update`
- `--skip-java-db-update`

---

## Security notes

- The report may contain secret-like fragments (`match`). Treat results as sensitive.
- Remote mode scans registry artifacts: ensure you have access and that registry usage policy allows it.

---

## Pipeline-friendly example

Because **stdout** prints only the report filename, you can do:
```bash
REPORT="$(python3 trivy-scanner.py --mode remote --jobs-remote 4)"
echo "Saved report: $REPORT"
```
