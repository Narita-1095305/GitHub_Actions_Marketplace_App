# Dep-Risk: Dependency Vulnerability Scanner with Risk Scoring

[![Go Tests](https://github.com/dep-risk/dep-risk/actions/workflows/test.yml/badge.svg)](https://github.com/dep-risk/dep-risk/actions/workflows/test.yml)
[![Security Scan](https://github.com/dep-risk/dep-risk/actions/workflows/security.yml/badge.svg)](https://github.com/dep-risk/dep-risk/actions/workflows/security.yml)

A GitHub Actions marketplace app that scans project dependencies for vulnerabilities and calculates risk scores to help teams make informed security decisions.

## 🚀 Features

- **Multi-language Support**: Go, Node.js (Python, Java coming soon)
- **Advanced Risk Scoring**: CVSS + Popularity + Dependency Type + Context
- **GitHub Integration**: PR comments, Check Runs, Security tab (SARIF)
- **Configurable Thresholds**: Customizable fail/warn thresholds
- **Rich Reporting**: JSON, SARIF, and human-readable formats

## 📊 Risk Scoring Algorithm

Dep-Risk calculates risk scores (0-10) using a weighted combination of factors:

- **CVSS Score (50%)**: Base vulnerability severity
- **Package Popularity (20%)**: Less popular packages may have fewer security reviews
- **Dependency Type (15%)**: Direct dependencies are easier to update than transitive ones
- **Context (15%)**: Package type and usage context (crypto, network, auth libraries are higher risk)

## 🔧 Quick Start

### 1. Add to your GitHub Actions workflow

```yaml
name: Security Scan
on: [pull_request, push]

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      checks: write
      pull-requests: write
      security-events: write
      contents: read
    
    steps:
    - uses: actions/checkout@v4
    - uses: dep-risk/dep-risk@v1
      with:
        fail_threshold: 7.0
        warn_threshold: 3.0
        github_token: ${{ secrets.GITHUB_TOKEN }}
```

### 2. Configure (optional)

Create `.github/dep-risk.yml`:

```yaml
fail_threshold: 7.0
warn_threshold: 3.0
cvss_weight: 0.5
popularity_weight: 0.2
dependency_weight: 0.15
context_weight: 0.15
comment_mode: "on-failure"
sarif_upload: true
ignore_list:
  - "CVE-2023-1234"  # Example: ignore specific CVEs
```

## 📝 Configuration Options

| Parameter | Description | Default |
|-----------|-------------|---------|
| `fail_threshold` | Risk score threshold to fail CI (0-10) | `7.0` |
| `warn_threshold` | Risk score threshold for warnings (0-10) | `3.0` |
| `cvss_weight` | Weight for CVSS component (0.0-1.0) | `0.5` |
| `popularity_weight` | Weight for popularity component (0.0-1.0) | `0.2` |
| `dependency_weight` | Weight for dependency type component (0.0-1.0) | `0.15` |
| `context_weight` | Weight for context component (0.0-1.0) | `0.15` |
| `comment_mode` | PR comment behavior: `always`, `on-failure`, `never` | `on-failure` |
| `sarif_upload` | Upload SARIF to GitHub Security tab | `true` |
| `languages` | Languages to scan: `auto`, `go`, `nodejs`, etc. | `auto` |
| `exclude_paths` | Comma-separated paths to exclude | `node_modules,vendor,.git` |

## 🏗️ Local Development

### Prerequisites

```bash
# Install scanning tools
brew install syft osv-scanner

# Or using curl
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
go install github.com/google/osv-scanner/cmd/osv-scanner@latest
```

### Build and Test

```bash
# Clone the repository
git clone https://github.com/dep-risk/dep-risk.git
cd dep-risk

# Build the CLI
go build -o dep-risk-cli ./cmd/action

# Run tests
go test ./...

# Test on a sample project
cd test-sample-project
../dep-risk-cli
```

## 📊 Example Output

```
🔍 Starting vulnerability scan...
📊 Found 3 vulnerabilities
⚖️  Calculating risk scores...

📋 Scan Summary:
   Overall Risk Score: 6.5/10
   Total Vulnerabilities: 3
   High Risk: 1 | Medium Risk: 1 | Low Risk: 1
   Average Score: 5.2

🔍 Top Vulnerabilities:
   • CVE-2023-1234 in express v4.17.1 (Score: 8.2, CVSS: 8.5)
   • CVE-2023-5678 in lodash v4.17.20 (Score: 4.8, CVSS: 4.3)

✅ Scan passed: Risk score 6.5 is below threshold 7.0
```

## 🔒 Security

- **No Data Collection**: Dep-Risk doesn't collect or store your project data
- **Local Processing**: All scanning happens in your GitHub Actions runner
- **Minimal Permissions**: Only requires necessary GitHub permissions
- **Signed Releases**: All releases are signed with Cosign

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Install dependencies
go mod tidy

# Run tests with coverage
go test -cover ./...

# Run linter
golangci-lint run

# Build Docker image
docker build -t dep-risk .
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- 📖 [Documentation](https://docs.deprisk.io)
- 🐛 [Issue Tracker](https://github.com/dep-risk/dep-risk/issues)
- 💬 [Discussions](https://github.com/dep-risk/dep-risk/discussions)
- 📧 [Email Support](mailto:support@deprisk.io)

## 🗺️ Roadmap

- [ ] **Phase 2**: Dashboard and API backend
- [ ] **Phase 3**: Multi-language support (Python, Java, Rust)
- [ ] **Phase 4**: Advanced features (ML-based scoring, policy engine)
- [ ] **Phase 5**: Enterprise features (SSO, audit logs, compliance reports)

---

Made with ❤️ by the Dep-Risk team