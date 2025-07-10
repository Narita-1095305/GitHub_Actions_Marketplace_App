# GitHub Actions統合 - 実装詳細設計

## 1. 概要

### 1.1 統合アーキテクチャ
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   GitHub Event  │───▶│  Action Runtime  │───▶│  Backend API    │
│  (PR/Schedule)  │    │   (Docker)       │    │  (Aggregation)  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌──────────────────┐
                       │  GitHub API      │
                       │ (Comments/Checks)│
                       └──────────────────┘
```

### 1.2 主要コンポーネント
- **action.yml**: GitHub Actions メタデータとインターフェース定義
- **Docker環境**: 軽量で高速な実行環境
- **GitHub API連携**: PR コメント、Check Runs、SARIF アップロード
- **並列処理**: 複数ファイルの効率的なスキャン
- **キャッシュ戦略**: 脆弱性DBとスキャン結果の最適化

## 2. action.yml 設計

### 2.1 完全なaction.yml仕様

```yaml
name: 'Dep-Risk Scanner'
description: 'Dependency vulnerability scanner with risk scoring'
author: 'Dep-Risk Team'
branding:
  icon: 'shield'
  color: 'red'

inputs:
  # === Core Configuration ===
  fail_threshold:
    description: 'Risk score threshold to fail the check (0-10)'
    required: false
    default: '7.0'
  
  warn_threshold:
    description: 'Risk score threshold to show warnings (0-10)'
    required: false
    default: '3.0'
  
  scan_paths:
    description: 'Comma-separated paths to scan (default: auto-detect)'
    required: false
    default: ''
  
  exclude_paths:
    description: 'Comma-separated paths to exclude from scanning'
    required: false
    default: 'node_modules,vendor,.git'
  
  # === Language Support ===
  languages:
    description: 'Languages to scan (go,nodejs,python,java) or "auto"'
    required: false
    default: 'auto'
  
  # === Scoring Configuration ===
  scoring_config:
    description: 'Path to custom scoring configuration file'
    required: false
    default: '.github/dep-risk.yml'
  
  cvss_weight:
    description: 'Weight for CVSS component (0.0-1.0)'
    required: false
    default: '0.5'
  
  popularity_weight:
    description: 'Weight for popularity component (0.0-1.0)'
    required: false
    default: '0.2'
  
  dependency_weight:
    description: 'Weight for dependency depth component (0.0-1.0)'
    required: false
    default: '0.15'
  
  context_weight:
    description: 'Weight for context component (0.0-1.0)'
    required: false
    default: '0.15'
  
  # === Output Configuration ===
  comment_mode:
    description: 'PR comment mode (always,on-failure,never)'
    required: false
    default: 'on-failure'
  
  sarif_upload:
    description: 'Upload SARIF results to GitHub Security tab'
    required: false
    default: 'true'
  
  dashboard_upload:
    description: 'Upload results to Dep-Risk dashboard'
    required: false
    default: 'true'
  
  # === Advanced Options ===
  timeout:
    description: 'Scan timeout in seconds'
    required: false
    default: '300'
  
  parallel_jobs:
    description: 'Number of parallel scanning jobs'
    required: false
    default: '4'
  
  cache_enabled:
    description: 'Enable vulnerability database caching'
    required: false
    default: 'true'
  
  cache_ttl:
    description: 'Cache TTL in hours'
    required: false
    default: '24'
  
  # === Authentication ===
  github_token:
    description: 'GitHub token for API access'
    required: false
    default: ${{ github.token }}
  
  api_endpoint:
    description: 'Dep-Risk API endpoint'
    required: false
    default: 'https://api.deprisk.io'
  
  api_key:
    description: 'Dep-Risk API key (for dashboard features)'
    required: false
    default: ''

outputs:
  risk_score:
    description: 'Overall risk score (0-10)'
  
  vulnerabilities_found:
    description: 'Number of vulnerabilities found'
  
  high_risk_count:
    description: 'Number of high-risk vulnerabilities'
  
  scan_status:
    description: 'Scan status (success,failure,warning)'
  
  sarif_file:
    description: 'Path to generated SARIF file'
  
  report_url:
    description: 'URL to detailed report on dashboard'

runs:
  using: 'docker'
  image: 'Dockerfile'
  env:
    GITHUB_TOKEN: ${{ inputs.github_token }}
    DEP_RISK_API_KEY: ${{ inputs.api_key }}
    DEP_RISK_API_ENDPOINT: ${{ inputs.api_endpoint }}
```

### 2.2 設定ファイル (.github/dep-risk.yml)

```yaml
# Dep-Risk Configuration File
version: "1.0"

# Scoring Configuration
scoring:
  weights:
    cvss: 0.5
    popularity: 0.2
    dependency: 0.15
    context: 0.15
  
  modifiers:
    language:
      go: 1.0
      nodejs: 1.1      # Node.jsは脆弱性が多い傾向
      python: 1.05
      java: 0.95
    
    industry:
      fintech: 1.2     # 金融系は厳しく
      healthcare: 1.15
      ecommerce: 1.1
      default: 1.0

# Thresholds
thresholds:
  fail: 7.0
  warn: 3.0
  
# Ignore Rules
ignore:
  # CVE ID による無視
  cves:
    - "CVE-2021-44228"  # 一時的に無視
  
  # パッケージによる無視
  packages:
    - name: "lodash"
      version: "<4.17.21"
      reason: "Legacy code, planned upgrade in Q2"
      expires: "2024-06-30"
  
  # パスによる無視
  paths:
    - "test/**"
    - "examples/**"
    - "docs/**"

# Language-specific settings
languages:
  go:
    files: ["go.mod", "go.sum"]
    exclude_test_deps: true
  
  nodejs:
    files: ["package.json", "package-lock.json", "yarn.lock"]
    include_dev_deps: false
  
  python:
    files: ["requirements.txt", "Pipfile.lock", "pyproject.toml"]
    include_dev_deps: false

# Output Configuration
output:
  comment:
    mode: "on-failure"  # always, on-failure, never
    template: "default" # default, minimal, detailed
  
  sarif:
    enabled: true
    include_low_severity: false
  
  dashboard:
    enabled: true
    project_name: ""  # Auto-detect from repo name
    team: ""          # Optional team identifier

# Advanced Options
advanced:
  timeout: 300
  parallel_jobs: 4
  cache_ttl: 24
  retry_attempts: 3
  
  # Custom vulnerability sources
  vulnerability_sources:
    - "osv"
    - "nvd"
    # - "custom-db"  # Enterprise feature
```

## 3. Docker環境設計

### 3.1 Dockerfile

```dockerfile
# Multi-stage build for optimal size and security
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o dep-risk ./cmd/action

# Install scanning tools
FROM alpine:3.18 AS tools

# Install syft
RUN wget -qO- https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Install osv-scanner
RUN wget -qO- https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64 -O /usr/local/bin/osv-scanner && \
    chmod +x /usr/local/bin/osv-scanner

# Final stage - distroless for security
FROM gcr.io/distroless/static:nonroot

# Copy CA certificates
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy timezone data
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy scanning tools
COPY --from=tools /usr/local/bin/syft /usr/local/bin/syft
COPY --from=tools /usr/local/bin/osv-scanner /usr/local/bin/osv-scanner

# Copy our application
COPY --from=builder /app/dep-risk /usr/local/bin/dep-risk

# Set user to non-root
USER 65532:65532

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/dep-risk"]
```

### 3.2 Docker最適化戦略

```yaml
# .dockerignore
.git
.github
*.md
test/
examples/
docs/
.gitignore
Dockerfile
docker-compose.yml
```

### 3.3 実行時最適化

```go
// pkg/docker/optimizer.go
package docker

import (
    "context"
    "runtime"
    "time"
)

type RuntimeOptimizer struct {
    MaxMemory    int64
    MaxCPU       int
    Timeout      time.Duration
    CacheEnabled bool
}

func NewRuntimeOptimizer() *RuntimeOptimizer {
    return &RuntimeOptimizer{
        MaxMemory:    1024 * 1024 * 1024, // 1GB
        MaxCPU:       runtime.NumCPU(),
        Timeout:      5 * time.Minute,
        CacheEnabled: true,
    }
}

func (ro *RuntimeOptimizer) OptimizeForGitHubActions() {
    // GitHub Actions runners have 2 CPU cores and 7GB RAM
    ro.MaxCPU = min(ro.MaxCPU, 2)
    ro.MaxMemory = min(ro.MaxMemory, 6*1024*1024*1024) // 6GB to be safe
}
```

## 4. GitHub API連携設計

### 4.1 API クライアント設計

```go
// pkg/github/client.go
package github

import (
    "context"
    "fmt"
    "github.com/google/go-github/v56/github"
    "golang.org/x/oauth2"
)

type Client struct {
    client *github.Client
    owner  string
    repo   string
    pr     int
}

type PRComment struct {
    RiskScore          float64
    VulnerabilitiesFound int
    HighRiskCount      int
    ReportURL          string
    ScanResults        []VulnerabilityResult
}

type CheckRun struct {
    Name        string
    Status      string // queued, in_progress, completed
    Conclusion  string // success, failure, neutral, cancelled, skipped, timed_out, action_required
    Summary     string
    Text        string
    Annotations []CheckAnnotation
}

type CheckAnnotation struct {
    Path            string
    StartLine       int
    EndLine         int
    AnnotationLevel string // notice, warning, failure
    Message         string
    Title           string
}

func NewClient(token, owner, repo string, pr int) *Client {
    ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
    tc := oauth2.NewClient(context.Background(), ts)
    
    return &Client{
        client: github.NewClient(tc),
        owner:  owner,
        repo:   repo,
        pr:     pr,
    }
}

func (c *Client) CreatePRComment(ctx context.Context, comment *PRComment) error {
    body := c.formatPRComment(comment)
    
    _, _, err := c.client.Issues.CreateComment(ctx, c.owner, c.repo, c.pr, &github.IssueComment{
        Body: &body,
    })
    
    return err
}

func (c *Client) CreateCheckRun(ctx context.Context, checkRun *CheckRun) error {
    _, _, err := c.client.Checks.CreateCheckRun(ctx, c.owner, c.repo, github.CreateCheckRunOptions{
        Name:       checkRun.Name,
        Status:     &checkRun.Status,
        Conclusion: &checkRun.Conclusion,
        Output: &github.CheckRunOutput{
            Title:       &checkRun.Name,
            Summary:     &checkRun.Summary,
            Text:        &checkRun.Text,
            Annotations: c.convertAnnotations(checkRun.Annotations),
        },
    })
    
    return err
}

func (c *Client) UploadSARIF(ctx context.Context, sarifFile string) error {
    // SARIF upload implementation
    // GitHub's SARIF upload API requires specific formatting
    return nil
}
```

### 4.2 PRコメントテンプレート

```go
// pkg/github/templates.go
package github

import (
    "fmt"
    "strings"
    "text/template"
)

const defaultPRCommentTemplate = `
## 🛡️ Dep-Risk Security Scan Results

### Overall Risk Score: {{.RiskScore}}/10 {{.RiskEmoji}}

{{if gt .VulnerabilitiesFound 0}}
**⚠️ {{.VulnerabilitiesFound}} vulnerabilities found** ({{.HighRiskCount}} high-risk)

### High-Risk Vulnerabilities
{{range .HighRiskVulnerabilities}}
| Package | Version | CVE | CVSS | Risk Score |
|---------|---------|-----|------|------------|
{{range .}}| {{.Package}} | {{.Version}} | {{.CVE}} | {{.CVSS}} | {{.RiskScore}} |
{{end}}
{{end}}

### Recommendations
{{range .Recommendations}}
- {{.}}
{{end}}

{{else}}
**✅ No vulnerabilities found!**
{{end}}

---
📊 [View detailed report]({{.ReportURL}}) | 🔧 [Configure thresholds](.github/dep-risk.yml)

<details>
<summary>Scan Details</summary>

- **Scan Duration**: {{.ScanDuration}}
- **Files Scanned**: {{.FilesScanned}}
- **Languages Detected**: {{.Languages}}
- **Scanner Version**: {{.ScannerVersion}}

</details>
`

func (c *Client) formatPRComment(comment *PRComment) string {
    tmpl := template.Must(template.New("pr-comment").Parse(defaultPRCommentTemplate))
    
    data := struct {
        *PRComment
        RiskEmoji              string
        HighRiskVulnerabilities []VulnerabilityResult
        Recommendations        []string
        ScanDuration           string
        FilesScanned           int
        Languages              string
        ScannerVersion         string
    }{
        PRComment: comment,
        RiskEmoji: c.getRiskEmoji(comment.RiskScore),
        // ... populate other fields
    }
    
    var buf strings.Builder
    tmpl.Execute(&buf, data)
    return buf.String()
}

func (c *Client) getRiskEmoji(score float64) string {
    switch {
    case score >= 7.0:
        return "🔴"
    case score >= 3.0:
        return "🟡"
    default:
        return "🟢"
    }
}
```

### 4.3 SARIF生成

```go
// pkg/sarif/generator.go
package sarif

import (
    "encoding/json"
    "fmt"
    "time"
)

type SARIFReport struct {
    Schema  string `json:"$schema"`
    Version string `json:"version"`
    Runs    []Run  `json:"runs"`
}

type Run struct {
    Tool    Tool     `json:"tool"`
    Results []Result `json:"results"`
}

type Tool struct {
    Driver Driver `json:"driver"`
}

type Driver struct {
    Name            string `json:"name"`
    Version         string `json:"version"`
    InformationURI  string `json:"informationUri"`
    Rules           []Rule `json:"rules"`
}

type Rule struct {
    ID               string           `json:"id"`
    Name             string           `json:"name"`
    ShortDescription MessageString    `json:"shortDescription"`
    FullDescription  MessageString    `json:"fullDescription"`
    Help             MessageString    `json:"help"`
    Properties       RuleProperties   `json:"properties"`
}

type Result struct {
    RuleID    string     `json:"ruleId"`
    Level     string     `json:"level"` // error, warning, note
    Message   MessageString `json:"message"`
    Locations []Location `json:"locations"`
}

type Location struct {
    PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

type PhysicalLocation struct {
    ArtifactLocation ArtifactLocation `json:"artifactLocation"`
    Region           Region           `json:"region"`
}

type ArtifactLocation struct {
    URI string `json:"uri"`
}

type Region struct {
    StartLine   int `json:"startLine"`
    StartColumn int `json:"startColumn"`
    EndLine     int `json:"endLine"`
    EndColumn   int `json:"endColumn"`
}

type MessageString struct {
    Text string `json:"text"`
}

type RuleProperties struct {
    Tags             []string `json:"tags"`
    SecuritySeverity string   `json:"security-severity"`
}

func GenerateSARIF(vulnerabilities []VulnerabilityResult) (*SARIFReport, error) {
    report := &SARIFReport{
        Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        Version: "2.1.0",
        Runs: []Run{
            {
                Tool: Tool{
                    Driver: Driver{
                        Name:           "Dep-Risk",
                        Version:        "1.0.0",
                        InformationURI: "https://github.com/dep-risk/dep-risk",
                        Rules:          generateRules(vulnerabilities),
                    },
                },
                Results: generateResults(vulnerabilities),
            },
        },
    }
    
    return report, nil
}

func generateRules(vulnerabilities []VulnerabilityResult) []Rule {
    ruleMap := make(map[string]Rule)
    
    for _, vuln := range vulnerabilities {
        if _, exists := ruleMap[vuln.CVE]; !exists {
            ruleMap[vuln.CVE] = Rule{
                ID:   vuln.CVE,
                Name: fmt.Sprintf("Vulnerability %s", vuln.CVE),
                ShortDescription: MessageString{
                    Text: vuln.Summary,
                },
                FullDescription: MessageString{
                    Text: vuln.Description,
                },
                Help: MessageString{
                    Text: fmt.Sprintf("For more information, see: %s", vuln.URL),
                },
                Properties: RuleProperties{
                    Tags:             []string{"security", "vulnerability"},
                    SecuritySeverity: fmt.Sprintf("%.1f", vuln.RiskScore),
                },
            }
        }
    }
    
    rules := make([]Rule, 0, len(ruleMap))
    for _, rule := range ruleMap {
        rules = append(rules, rule)
    }
    
    return rules
}
```

## 5. 並列処理とキャッシュ戦略

### 5.1 並列スキャン実装

```go
// pkg/scanner/parallel.go
package scanner

import (
    "context"
    "sync"
    "runtime"
)

type ParallelScanner struct {
    maxWorkers int
    semaphore  chan struct{}
}

func NewParallelScanner(maxWorkers int) *ParallelScanner {
    if maxWorkers <= 0 {
        maxWorkers = runtime.NumCPU()
    }
    
    return &ParallelScanner{
        maxWorkers: maxWorkers,
        semaphore:  make(chan struct{}, maxWorkers),
    }
}

func (ps *ParallelScanner) ScanFiles(ctx context.Context, files []string) ([]ScanResult, error) {
    results := make([]ScanResult, len(files))
    var wg sync.WaitGroup
    var mu sync.Mutex
    var firstError error
    
    for i, file := range files {
        wg.Add(1)
        go func(index int, filepath string) {
            defer wg.Done()
            
            // Acquire semaphore
            ps.semaphore <- struct{}{}
            defer func() { <-ps.semaphore }()
            
            result, err := ps.scanSingleFile(ctx, filepath)
            
            mu.Lock()
            defer mu.Unlock()
            
            if err != nil && firstError == nil {
                firstError = err
                return
            }
            
            results[index] = result
        }(i, file)
    }
    
    wg.Wait()
    return results, firstError
}
```

### 5.2 キャッシュシステム

```go
// pkg/cache/vulnerability.go
package cache

import (
    "crypto/sha256"
    "encoding/json"
    "fmt"
    "os"
    "path/filepath"
    "time"
)

type VulnerabilityCache struct {
    cacheDir string
    ttl      time.Duration
}

type CacheEntry struct {
    Data      interface{} `json:"data"`
    Timestamp time.Time   `json:"timestamp"`
    Version   string      `json:"version"`
}

func NewVulnerabilityCache(cacheDir string, ttl time.Duration) *VulnerabilityCache {
    return &VulnerabilityCache{
        cacheDir: cacheDir,
        ttl:      ttl,
    }
}

func (vc *VulnerabilityCache) Get(key string) (interface{}, bool) {
    cacheFile := vc.getCacheFilePath(key)
    
    data, err := os.ReadFile(cacheFile)
    if err != nil {
        return nil, false
    }
    
    var entry CacheEntry
    if err := json.Unmarshal(data, &entry); err != nil {
        return nil, false
    }
    
    // Check if cache is expired
    if time.Since(entry.Timestamp) > vc.ttl {
        os.Remove(cacheFile)
        return nil, false
    }
    
    return entry.Data, true
}

func (vc *VulnerabilityCache) Set(key string, data interface{}) error {
    entry := CacheEntry{
        Data:      data,
        Timestamp: time.Now(),
        Version:   "1.0",
    }
    
    jsonData, err := json.Marshal(entry)
    if err != nil {
        return err
    }
    
    cacheFile := vc.getCacheFilePath(key)
    os.MkdirAll(filepath.Dir(cacheFile), 0755)
    
    return os.WriteFile(cacheFile, jsonData, 0644)
}

func (vc *VulnerabilityCache) getCacheFilePath(key string) string {
    hash := sha256.Sum256([]byte(key))
    filename := fmt.Sprintf("%x.json", hash)
    return filepath.Join(vc.cacheDir, filename)
}
```

## 6. エラーハンドリングと監視

### 6.1 エラーハンドリング戦略

```go
// pkg/errors/handler.go
package errors

import (
    "fmt"
    "log"
)

type ErrorLevel int

const (
    ErrorLevelInfo ErrorLevel = iota
    ErrorLevelWarning
    ErrorLevelError
    ErrorLevelCritical
)

type ActionError struct {
    Level   ErrorLevel
    Code    string
    Message string
    Cause   error
}

func (ae *ActionError) Error() string {
    if ae.Cause != nil {
        return fmt.Sprintf("[%s] %s: %v", ae.Code, ae.Message, ae.Cause)
    }
    return fmt.Sprintf("[%s] %s", ae.Code, ae.Message)
}

type ErrorHandler struct {
    failOnError bool
}

func NewErrorHandler(failOnError bool) *ErrorHandler {
    return &ErrorHandler{failOnError: failOnError}
}

func (eh *ErrorHandler) Handle(err *ActionError) {
    switch err.Level {
    case ErrorLevelInfo:
        log.Printf("INFO: %s", err.Message)
    case ErrorLevelWarning:
        log.Printf("WARNING: %s", err.Message)
        fmt.Printf("::warning::%s\n", err.Message)
    case ErrorLevelError:
        log.Printf("ERROR: %s", err.Error())
        fmt.Printf("::error::%s\n", err.Message)
        if eh.failOnError {
            os.Exit(1)
        }
    case ErrorLevelCritical:
        log.Printf("CRITICAL: %s", err.Error())
        fmt.Printf("::error::%s\n", err.Message)
        os.Exit(1)
    }
}
```

### 6.2 メトリクス収集

```go
// pkg/metrics/collector.go
package metrics

import (
    "time"
)

type Metrics struct {
    ScanDuration     time.Duration
    FilesScanned     int
    VulnerabilitiesFound int
    CacheHitRate     float64
    MemoryUsage      int64
    ErrorCount       int
}

type Collector struct {
    startTime time.Time
    metrics   *Metrics
}

func NewCollector() *Collector {
    return &Collector{
        startTime: time.Now(),
        metrics: &Metrics{},
    }
}

func (c *Collector) RecordScanComplete() {
    c.metrics.ScanDuration = time.Since(c.startTime)
}

func (c *Collector) GetMetrics() *Metrics {
    return c.metrics
}
```

この設計により、効率的で拡張可能なGitHub Actions統合を実現できます。次に実装したい領域はどれでしょうか？

1. **脆弱性検出エンジンの最適化** - syft + osv-scannerの統合詳細
2. **Backend API アーキテクチャ** - ダッシュボード用のデータ集約システム
3. **Dashboard UX/UI設計** - リアルタイムヒートマップの実装
4. **セキュリティ・認証システム** - GitHub OIDC統合の詳細