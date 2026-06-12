# ShieldFlow — AppSec Pipeline

![ShieldFlow Pipeline](https://github.com/WaheedX-code/shieldflow/actions/workflows/trigger.yml/badge.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-Reusable_Workflow-2088FF?logo=github-actions)
![Security Tools](https://img.shields.io/badge/Tools-Semgrep%20%7C%20Trivy%20%7C%20Gitleaks%20%7C%20ZAP-green)

ShieldFlow is a reusable GitHub Actions security pipeline that automatically scans your code and running applications for vulnerabilities. It integrates four industry-standard security tools into a single workflow, covering static analysis, dependency scanning, secret detection, and dynamic application testing — all reporting directly to your GitHub Security tab.

-----

## Table of Contents

- [Overview](#overview)
- [Security Tools](#security-tools)
- [How It Works](#how-it-works)
- [Quick Start](#quick-start)
- [Inputs & Secrets](#inputs--secrets)
- [Scanning Scenarios](#scanning-scenarios)
- [Viewing Results](#viewing-results)
- [Docker Image Scanning](#docker-image-scanning)
- [Test Targets](#test-targets)
- [SOAR Integration](#soar-integration)
- [Requirements](#requirements)
- [Contributing](#contributing)
- [License](#license)

-----

## Overview

ShieldFlow is designed to give developers and security teams a **zero-setup security pipeline**. Instead of configuring individual tools, you simply reference this reusable workflow in your repository and ShieldFlow handles the rest.

It covers the full development lifecycle:

- **Before deployment** — scan your code, dependencies, and secrets on every push or pull request
- **After deployment** — dynamically attack your live application to uncover runtime vulnerabilities

-----

## Security Tools

|Tool                            |Type             |What It Scans                                     |Findings Location  |
|--------------------------------|-----------------|--------------------------------------------------|-------------------|
|[Semgrep](https://semgrep.dev)  |SAST             |Source code vulnerabilities (OWASP Top 10)        |GitHub Security tab|
|[Trivy](https://trivy.dev)      |SCA              |Dependencies, packages, container images (CVEs)   |GitHub Security tab|
|[Gitleaks](https://gitleaks.io) |Secrets Detection|Exposed API keys, tokens, passwords in git history|GitHub Security tab|
|[OWASP ZAP](https://zaproxy.org)|DAST             |Live/running application attacks                  |Actions Artifacts  |

-----

## How It Works

ShieldFlow runs as a **reusable workflow** — meaning you call it from your own repository without copying any configuration. All tools are pre-configured and results are automatically uploaded to your repository’s GitHub Security tab.

```
Dev pushes code
      ↓
Semgrep scans source code for vulnerabilities
Trivy scans dependencies and container images
Gitleaks scans git history for exposed secrets
      ↓
Results → GitHub Security tab (Code scanning alerts)
      ↓
Dev deploys app → Runs pipeline with target URL
      ↓
ZAP dynamically attacks the running application
      ↓
ZAP report → Actions Artifacts
      ↓
All findings → SOAR (if configured)
```

-----

## Quick Start

**Step 1** — In your repository, create the file `.github/workflows/scan.yml`

**Step 2** — Add the following content:

```yaml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  workflow_dispatch:
    inputs:
      target-url:
        description: 'URL of your running application to scan'
        required: false
        type: string
      target-image:
        description: 'Docker image to spin up for scanning (optional)'
        required: false
        type: string
      target-port:
        description: 'Port the application runs on (optional)'
        required: false
        type: string

permissions:
  security-events: write
  actions: read
  contents: read

jobs:
  security-scan:
    uses: WaheedX-code/shieldflow/.github/workflows/shieldflow.yml@main
    with:
      target-url: ${{ inputs.target-url || '' }}
      target-image: ${{ inputs.target-image || '' }}
      target-port: ${{ inputs.target-port || '3000' }}
    secrets:
      shuffle-webhook-url: ${{ secrets.SHUFFLE_WEBHOOK_URL }}
```

**Step 3** — Push to GitHub. The pipeline runs automatically.

-----

## Inputs & Secrets

### Inputs

|Input         |Required|Default|Description                                    |
|--------------|--------|-------|-----------------------------------------------|
|`target-url`  |No      |`''`   |URL of the running application to scan with ZAP|
|`target-image`|No      |`''`   |Docker image to spin up and scan               |
|`target-port` |No      |`''`   |Port the application runs on                   |

### Secrets

|Secret               |Required|Description                                         |
|---------------------|--------|----------------------------------------------------|
|`SHUFFLE_WEBHOOK_URL`|No      |Your Shuffle SOAR webhook URL for findings ingestion|

**Adding secrets to your repository:**

Go to: **Your repo → Settings → Secrets and variables → Actions → New repository secret**

-----

## Scanning Scenarios

### Scenario 1 — Code scan on push or pull request

Triggers automatically when you push code or open a pull request. No additional configuration needed.

**Tools that run:** Semgrep  Trivy  Gitleaks 

**ZAP:** Skipped (no target URL provided)

-----

### Scenario 2 — Live application scan (manual)

Trigger manually when your application is deployed and running.

1. Go to **Actions → Security Scan → Run workflow**
1. Enter your application URL in the `target-url` field
1. Click **Run workflow**

**Tools that run:** Semgrep  Trivy  Gitleaks  ZAP 

-----

### Scenario 3 — Full scan with Docker image

Provide a Docker image and ShieldFlow will spin it up, scan both the image and the running container.

```yaml
with:
  target-url: 'http://localhost:3000'
  target-image: 'your-docker-image:tag'
  target-port: '3000'
```

**Tools that run:** Semgrep  Trivy (image + filesystem)  Gitleaks  ZAP 

-----

##  Viewing Results

### GitHub Security Tab

All SAST, SCA, and Secrets findings are uploaded in SARIF format and appear here:

**Your repo → Security → Code scanning alerts**

Each alert includes:

- Severity level (Critical, High, Medium, Low)
- Affected file and line number
- Vulnerability description
- Recommended fix

### ZAP Report

ZAP findings are available as a downloadable artifact:

**Actions → Your workflow run → Artifacts → zap-dast-results**

-----

##  Docker Image Scanning

ShieldFlow can spin up a Docker container, scan the image for CVEs with Trivy, and then run ZAP against the live container — all automatically.

```yaml
jobs:
  security-scan:
    uses: WaheedX-code/shieldflow/.github/workflows/shieldflow.yml@main
    with:
      target-url: 'http://localhost:3000'
      target-image: 'myapp:latest'
      target-port: '3000'
    secrets:
      shuffle-webhook-url: ${{ secrets.SHUFFLE_WEBHOOK_URL }}
```

-----

##  Test Targets

Don’t have a live app yet? Use these intentionally vulnerable applications to test ShieldFlow:

|Target            |URL                         |Description                                         |
|------------------|----------------------------|----------------------------------------------------|
|Acunetix Test Site|`http://testphp.vulnweb.com`|PHP vulnerable web app                              |
|Altoro Mutual     |`http://demo.testfire.net`  |IBM’s fake banking app                              |
|DVWA (Docker)     |`http://localhost:8080`     |Run: `docker run -d -p 8080:80 vulnerables/web-dvwa`|

-----

##  SOAR Integration

ShieldFlow supports optional integration with **Shuffle SOAR** for automated incident response. When configured, all findings from all tools are posted to your Shuffle webhook after each scan.

**Setup:**

1. Get your webhook URL from Shuffle
1. Add it as `SHUFFLE_WEBHOOK_URL` in your repo secrets
1. ShieldFlow handles the rest automatically

If `SHUFFLE_WEBHOOK_URL` is not set, the SOAR notification step is silently skipped.

-----

##  Requirements

- GitHub repository with **GitHub Actions enabled**
- For DAST scanning: a **publicly accessible** running application URL
- For Docker scanning: a valid **Docker image** accessible to GitHub Actions runners
- Repository must have **Code scanning** enabled (free for public repos)

-----

## Contributors
- [WaheedX-code] (https://github.com/WaheedX-code) - Pipeline architecture, SCA, DAST, break gates
- [funke038] (https://github.com/funke038) - SOAR engineering, playbooks, CVE enrichment

##  Contributing

Contributions are welcome! Here’s how to get started:

1. Fork the repository
1. Create a feature branch: `git checkout -b feature/your-feature`
1. Commit your changes: `git commit -m 'Add your feature'`
1. Push to the branch: `git push origin feature/your-feature`
1. Open a Pull Request

For major changes, please open an issue first to discuss what you’d like to change.

-----

## License

This project is licensed under the MIT License — see the <LICENSE> file for details.

-----

<p align="center">Built with ❤️ by <a href="https://github.com/WaheedX-code">WaheedX-code</a></p>
