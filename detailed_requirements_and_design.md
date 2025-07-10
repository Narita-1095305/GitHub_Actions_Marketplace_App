# Dep-Risk: 詳細要件・設計書

## 1. プロジェクト概要

### 1.1 目的
依存ライブラリの脆弱性を自動検出し、リスクスコアを算出してCI/CDパイプラインに統合するGitHub Actions Marketplace アプリケーション

### 1.2 対象ユーザー
- **開発者**: PR時の脆弱性自動チェック
- **Tech Lead/SRE**: 複数リポジトリのリスク一元管理
- **セキュリティ担当**: 組織全体のCVE状況監視
- **OSSメンテナ**: 悪意あるパッケージの自動ブロック

## 2. 機能要件

### 2.1 コア機能

#### 2.1.1 脆弱性スキャン機能
- **入力対象ファイル**:
  - Go: `go.sum`, `go.mod`
  - Node.js: `package-lock.json`, `package.json`
  - Python: `requirements.txt`, `Pipfile.lock` (将来拡張)
  - Java: `pom.xml`, `gradle.lock` (将来拡張)

- **検出エンジン**:
  - SBOM生成: [syft](https://github.com/anchore/syft)
  - CVE照合: [osv-scanner](https://github.com/google/osv-scanner)
  - 脆弱性データベース: OSV Database + NVD

#### 2.1.2 リスクスコア算定
- **スコア範囲**: 0-10 (10が最高リスク)
- **算定要素**:
  - CVSS Base Score (重み: 70%)
  - パッケージ人気度 (GitHub Stars, NPM Downloads等) (重み: 20%)
  - 依存関係の深さ (重み: 10%)

- **スコア計算式**:
  ```
  Risk Score = (CVSS × 0.7) + (Popularity Factor × 0.2) + (Dependency Depth × 0.1)
  
  Popularity Factor = max(0, 10 - log10(downloads_per_month / 1000))
  Dependency Depth = min(10, direct_dependency ? 0 : transitive_depth × 2)
  ```

### 2.2 GitHub Actions統合

#### 2.2.1 Action設定
```yaml
name: Dependency Risk Check
on:
  pull_request:
    types: [opened, synchronize]
  schedule:
    - cron: '0 2 * * *'  # 毎日2時に実行

jobs:
  dep-risk:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: org/dep-risk@v1
        with:
          fail_threshold: 7.0
          config_path: .github/dep-risk.yml
          upload_sarif: true
          dashboard_enabled: true
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

#### 2.2.2 設定ファイル (.github/dep-risk.yml)
```yaml
# Dep-Risk Configuration
version: 1

# スコアリング設定
scoring:
  cvss_weight: 0.7
  popularity_weight: 0.2
  depth_weight: 0.1
  
# しきい値設定
thresholds:
  fail_score: 7.0      # CI失敗となるスコア
  warn_score: 5.0      # 警告表示するスコア
  
# 除外設定
ignore:
  packages:
    - "lodash@4.17.20"  # 特定バージョンを除外
    - "express@*"       # パッケージ全体を除外
  cves:
    - "CVE-2021-44228"  # 特定CVEを除外
  paths:
    - "test/**"         # テストディレクトリを除外
    - "docs/**"

# 通知設定
notifications:
  slack:
    webhook_url: ${{ secrets.SLACK_WEBHOOK }}
    channel: "#security-alerts"
  email:
    recipients:
      - "security@company.com"
```

### 2.3 出力機能

#### 2.3.1 PR コメント
```markdown
## 🔍 Dependency Risk Analysis

### Summary
- **Total Packages Scanned**: 127
- **Vulnerabilities Found**: 3
- **Highest Risk Score**: 8.2/10 ⚠️

### High Risk Dependencies
| Package | Version | CVE | CVSS | Risk Score | Recommendation |
|---------|---------|-----|------|------------|----------------|
| lodash | 4.17.15 | CVE-2021-23337 | 7.2 | 8.2 | Update to 4.17.21+ |
| express | 4.16.0 | CVE-2022-24999 | 6.1 | 7.1 | Update to 4.18.0+ |

### Action Required
❌ **CI Check Failed** - Risk score 8.2 exceeds threshold 7.0

[View detailed report](https://app.deprisk.io/reports/abc123)
```

#### 2.3.2 SARIF出力 (GitHub Security タブ統合)
```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "Dep-Risk",
        "version": "1.0.0"
      }
    },
    "results": [{
      "ruleId": "DEP-RISK-001",
      "level": "error",
      "message": {
        "text": "High risk dependency: lodash@4.17.15 (CVE-2021-23337, Score: 8.2)"
      },
      "locations": [{
        "physicalLocation": {
          "artifactLocation": {
            "uri": "package-lock.json"
          },
          "region": {
            "startLine": 1234
          }
        }
      }]
    }]
  }]
}
```

## 3. システム設計

### 3.1 アーキテクチャ概要

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   GitHub        │    │   GitHub Actions │    │   Backend API   │
│   Repository    │───▶│   (Dep-Risk)     │───▶│   (Go + Postgres│
│                 │    │                  │    │    + Redis)     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │                        │
                                ▼                        ▼
                       ┌──────────────────┐    ┌─────────────────┐
                       │   PR Comments    │    │   Dashboard     │
                       │   SARIF Upload   │    │   (Next.js)     │
                       │   Check Runs     │    │                 │
                       └──────────────────┘    └─────────────────┘
```

### 3.2 GitHub Action (CLI) 設計

#### 3.2.1 ディレクトリ構造
```
dep-risk/
├── action.yml                 # GitHub Action定義
├── Dockerfile                 # Action実行環境
├── cmd/
│   └── dep-risk/
│       └── main.go            # CLI エントリーポイント
├── internal/
│   ├── scanner/               # スキャン機能
│   │   ├── sbom.go           # SBOM生成
│   │   ├── cve.go            # CVE検索
│   │   └── scorer.go         # スコア算定
│   ├── github/               # GitHub API統合
│   │   ├── comments.go       # PR コメント
│   │   ├── checks.go         # Check Runs
│   │   └── sarif.go          # SARIF アップロード
│   ├── config/               # 設定管理
│   │   └── config.go
│   └── api/                  # Backend API クライアント
│       └── client.go
├── pkg/
│   └── models/               # 共通データ構造
│       ├── vulnerability.go
│       ├── package.go
│       └── report.go
└── scripts/
    ├── build.sh              # ビルドスクリプト
    └── release.sh            # リリーススクリプト
```

#### 3.2.2 主要コンポーネント

**Scanner Package**
```go
type Scanner struct {
    sbomGenerator SBOMGenerator
    cveDatabase   CVEDatabase
    scorer        RiskScorer
}

type ScanResult struct {
    Packages        []Package        `json:"packages"`
    Vulnerabilities []Vulnerability  `json:"vulnerabilities"`
    RiskScore       float64         `json:"risk_score"`
    Timestamp       time.Time       `json:"timestamp"`
}

func (s *Scanner) ScanRepository(repoPath string) (*ScanResult, error)
```

**Risk Scorer**
```go
type RiskScorer struct {
    CVSSWeight       float64 `json:"cvss_weight"`
    PopularityWeight float64 `json:"popularity_weight"`
    DepthWeight      float64 `json:"depth_weight"`
}

func (rs *RiskScorer) CalculateScore(vuln Vulnerability, pkg Package) float64
```

### 3.3 Backend API 設計

#### 3.3.1 技術スタック
- **言語**: Go 1.21+
- **フレームワーク**: Gin
- **データベース**: PostgreSQL 15
- **キャッシュ**: Redis 7
- **認証**: GitHub OIDC Token
- **デプロイ**: AWS Fargate + ALB

#### 3.3.2 API エンドポイント

```go
// レポート投稿
POST /api/v1/reports
Authorization: Bearer <github-oidc-token>
Content-Type: application/json

{
  "repository": "owner/repo",
  "commit_sha": "abc123",
  "scan_result": { /* ScanResult */ },
  "metadata": {
    "workflow_run_id": "123456",
    "actor": "username"
  }
}

// 組織ダッシュボードデータ取得
GET /api/v1/organizations/{org}/dashboard
Authorization: Bearer <github-oidc-token>
Query: ?days=30&limit=100

Response:
{
  "repositories": [
    {
      "name": "owner/repo",
      "latest_score": 6.5,
      "trend": "improving",
      "last_scan": "2024-01-15T10:00:00Z",
      "vulnerability_count": 3
    }
  ],
  "summary": {
    "total_repos": 45,
    "high_risk_repos": 5,
    "avg_score": 4.2
  }
}

// 詳細レポート取得
GET /api/v1/reports/{report_id}
Authorization: Bearer <github-oidc-token>

Response: ScanResult + metadata
```

#### 3.3.3 データベース設計

```sql
-- 組織テーブル
CREATE TABLE organizations (
    id SERIAL PRIMARY KEY,
    github_org VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- リポジトリテーブル
CREATE TABLE repositories (
    id SERIAL PRIMARY KEY,
    org_id INTEGER REFERENCES organizations(id),
    name VARCHAR(255) NOT NULL,
    github_repo_id BIGINT UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(org_id, name)
);

-- スキャンレポートテーブル
CREATE TABLE scan_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repo_id INTEGER REFERENCES repositories(id),
    commit_sha VARCHAR(40) NOT NULL,
    risk_score DECIMAL(3,1) NOT NULL,
    vulnerability_count INTEGER NOT NULL,
    package_count INTEGER NOT NULL,
    scan_duration_ms INTEGER,
    workflow_run_id BIGINT,
    actor VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW(),
    
    INDEX idx_repo_created (repo_id, created_at DESC),
    INDEX idx_commit_sha (commit_sha),
    INDEX idx_risk_score (risk_score DESC)
);

-- 脆弱性詳細テーブル
CREATE TABLE vulnerabilities (
    id SERIAL PRIMARY KEY,
    report_id UUID REFERENCES scan_reports(id),
    package_name VARCHAR(255) NOT NULL,
    package_version VARCHAR(100) NOT NULL,
    cve_id VARCHAR(20),
    cvss_score DECIMAL(3,1),
    risk_score DECIMAL(3,1) NOT NULL,
    severity VARCHAR(20),
    description TEXT,
    
    INDEX idx_report_id (report_id),
    INDEX idx_cve_id (cve_id),
    INDEX idx_package (package_name, package_version)
);
```

### 3.4 Dashboard (Frontend) 設計

#### 3.4.1 技術スタック
- **フレームワーク**: Next.js 14 (App Router)
- **UI ライブラリ**: Chakra UI v2
- **状態管理**: Zustand
- **認証**: NextAuth.js (GitHub Provider)
- **チャート**: Recharts
- **デプロイ**: Vercel

#### 3.4.2 ページ構成

```
/
├── /                          # ランディングページ
├── /auth/signin              # ログイン
├── /dashboard                # 組織ダッシュボード
│   ├── /[org]               # 組織別ダッシュボード
│   │   ├── /repos           # リポジトリ一覧
│   │   ├── /reports/[id]    # 詳細レポート
│   │   └── /settings        # 設定
│   └── /personal            # 個人ダッシュボード
└── /docs                    # ドキュメント
```

#### 3.4.3 主要コンポーネント

**Risk Heatmap**
```tsx
interface RiskHeatmapProps {
  repositories: Repository[];
  timeRange: number; // days
}

const RiskHeatmap: React.FC<RiskHeatmapProps> = ({ repositories, timeRange }) => {
  // 200 repos × 30 days でも 1秒以内で表示
  // 色分け: 緑(0-3), 黄(3-7), 赤(7-10)
  // ホバーで詳細表示
};
```

**Trend Chart**
```tsx
interface TrendChartProps {
  data: RiskTrendData[];
  metric: 'score' | 'vulnerability_count';
}

const TrendChart: React.FC<TrendChartProps> = ({ data, metric }) => {
  // 時系列でリスクスコアの推移を表示
  // 週次/月次の集計切り替え
};
```

## 4. 非機能要件

### 4.1 パフォーマンス要件
- **スキャン時間**: 中規模プロジェクト(500パッケージ)で30秒以内
- **メモリ使用量**: GitHub Actions実行時 1GB以内
- **Dashboard応答時間**: 200リポジトリ×30日のデータで1秒以内
- **API応答時間**: 95%ile で 500ms以内

### 4.2 可用性要件
- **Backend SLA**: 99.9% (月間ダウンタイム 43分以内)
- **Dashboard SLA**: 99.5%
- **GitHub Actions**: GitHub Actionsの可用性に依存

### 4.3 セキュリティ要件
- **認証**: GitHub OIDC Token必須
- **認可**: リポジトリアクセス権限に基づく
- **データ保護**: 
  - ソースコードは保存しない
  - 個人情報は保存しない
  - 脆弱性情報のみ保存
- **通信**: HTTPS/TLS 1.3必須
- **Action署名**: Cosign署名必須

### 4.4 スケーラビリティ要件
- **同時実行**: 100並列GitHub Actions実行をサポート
- **データ量**: 10,000リポジトリ×365日のデータ保持
- **ユーザー数**: 1,000組織、10,000ユーザーをサポート

## 5. 実装計画

### 5.1 Phase 1: MVP (4週間)
- [ ] CLI基本機能 (Go/Node.js対応)
- [ ] GitHub Action統合
- [ ] 基本的なPRコメント機能
- [ ] シンプルなスコア算定

### 5.2 Phase 2: Backend & Dashboard (6週間)
- [ ] Backend API開発
- [ ] PostgreSQL設計・実装
- [ ] Dashboard基本機能
- [ ] 組織ダッシュボード

### 5.3 Phase 3: 高度な機能 (4週間)
- [ ] SARIF統合
- [ ] 詳細設定機能
- [ ] 通知機能 (Slack/Email)
- [ ] エクスポート機能

### 5.4 Phase 4: 本格運用 (2週間)
- [ ] パフォーマンス最適化
- [ ] セキュリティ監査
- [ ] ドキュメント整備
- [ ] Marketplace公開

## 6. 運用・保守

### 6.1 監視
- **メトリクス**: Prometheus + Grafana
- **ログ**: CloudWatch Logs
- **アラート**: PagerDuty連携
- **ヘルスチェック**: `/health` エンドポイント

### 6.2 更新戦略
- **CVEデータベース**: 日次自動更新
- **Action**: セマンティックバージョニング
- **Backend**: Blue-Green デプロイメント
- **Dashboard**: Vercel自動デプロイ

### 6.3 サポート
- **ドキュメント**: GitHub Pages
- **Issue追跡**: GitHub Issues
- **コミュニティ**: GitHub Discussions
- **エンタープライズサポート**: 有償オプション