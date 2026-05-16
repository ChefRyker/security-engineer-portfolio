# secure-cicd-pipeline

A GitHub Actions pipeline that builds security into every stage of the software delivery lifecycle — from commit to deployment. This repo is a working demonstration of DevSecOps practices.

## Pipeline Stages

```
 PR opened
     │
     ├── 1. Secret Scanning    (gitleaks)
     ├── 2. SAST               (Semgrep, Bandit for Python)
     ├── 3. SCA / Dependencies (pip-audit, Trivy)
     ├── 4. Container Scan     (Trivy image scan)
     ├── 5. SBOM Generation    (Syft → CycloneDX)
     │
     ▼
 Merge to main
     │
     ├── 6. Build & Push image (with provenance attestation)
     ├── 7. DAST               (OWASP ZAP baseline scan)
     └── 8. Deploy (staging → prod with approval gate)
```

## Workflows

| File | Trigger | Purpose |
|------|---------|---------|
| `security-scan.yml` | Every PR | SAST + secret scan + SCA |
| `container-scan.yml` | Every PR | Trivy image scan + SBOM |
| `dast.yml` | Merge to main | OWASP ZAP against staging |
| `dependency-check.yml` | Daily schedule | Full dependency audit |

## Why each tool

- **gitleaks** — prevents credentials from entering the repo at commit time
- **Semgrep** — pattern-based SAST; finds injection flaws, insecure defaults, CVE-specific patterns
- **Bandit** — Python-specific SAST; catches common Python security mistakes
- **pip-audit / Trivy SCA** — finds known CVEs in third-party packages
- **Trivy image scan** — scans the final container image layer by layer
- **Syft** — generates a Software Bill of Materials (SBOM) for supply chain visibility
- **OWASP ZAP** — DAST; hits the running app looking for XSS, injection, missing headers

## Running locally

```bash
# Secret scan
docker run --rm -v "$(pwd):/repo" zricethezav/gitleaks detect --source /repo

# SAST
semgrep --config=auto ./sample-app

# SCA
pip-audit -r sample-app/requirements.txt

# Container scan
trivy image your-image:latest
```
