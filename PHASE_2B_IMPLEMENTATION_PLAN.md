# フェーズ2B: ダッシュボード・API開発 実装計画

## 🎯 目標
組織レベルでの脆弱性可視化とリアルタイム監視システムの構築

## 📋 実装優先順位

### 1. バックエンドAPI開発 (最優先)
**目標**: GitHub Actionsからのデータ収集とAPI提供

#### 1.1 データベース設計・実装
- **PostgreSQL スキーマ設計**
  - Organizations テーブル
  - Repositories テーブル  
  - Scans テーブル
  - Vulnerabilities テーブル
  - Risk_Scores テーブル

#### 1.2 API サーバー実装 (`cmd/api/`)
- **認証・認可システム**
  - GitHub OIDC統合
  - JWT トークン管理
  - 組織レベル権限制御

- **REST API エンドポイント**
  - `POST /api/v1/scans` - スキャン結果投稿
  - `GET /api/v1/orgs/{org}/dashboard` - ダッシュボードデータ
  - `GET /api/v1/orgs/{org}/repos` - リポジトリ一覧
  - `GET /api/v1/repos/{repo}/history` - 履歴データ

#### 1.3 データ集約・分析機能
- **リアルタイム集計**
  - 組織全体のリスクスコア
  - リポジトリ別トレンド
  - 脆弱性タイプ別統計

### 2. フロントエンドダッシュボード開発
**目標**: 直感的で高速なWebダッシュボード

#### 2.1 Next.js + TypeScript セットアップ
- **技術スタック**
  - Next.js 14 (App Router)
  - TypeScript
  - Chakra UI v2
  - React Query (TanStack Query)
  - Chart.js / Recharts

#### 2.2 コア画面実装
- **組織ダッシュボード**
  - リアルタイムヒートマップ
  - リスクスコア分布
  - トップ脆弱性リスト

- **リポジトリ詳細画面**
  - 履歴トレンド
  - 脆弱性詳細
  - 修正提案

### 3. GitHub Actions統合拡張
**目標**: ダッシュボードへのデータ送信機能

#### 3.1 API クライアント実装
- **データ送信機能** (`internal/api/`)
  - スキャン結果の自動アップロード
  - 認証トークン管理
  - エラーハンドリング

## 🛠️ 技術仕様

### データベース設計
```sql
-- Organizations
CREATE TABLE organizations (
    id SERIAL PRIMARY KEY,
    github_org VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Repositories  
CREATE TABLE repositories (
    id SERIAL PRIMARY KEY,
    org_id INTEGER REFERENCES organizations(id),
    github_repo VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    language VARCHAR(50),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Scans
CREATE TABLE scans (
    id SERIAL PRIMARY KEY,
    repo_id INTEGER REFERENCES repositories(id),
    commit_sha VARCHAR(40),
    branch VARCHAR(255),
    overall_risk_score DECIMAL(3,1),
    total_vulnerabilities INTEGER,
    high_risk_count INTEGER,
    medium_risk_count INTEGER,
    low_risk_count INTEGER,
    scan_duration INTEGER, -- seconds
    created_at TIMESTAMP DEFAULT NOW()
);

-- Vulnerabilities
CREATE TABLE vulnerabilities (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id),
    cve_id VARCHAR(50),
    package_name VARCHAR(255),
    package_version VARCHAR(100),
    cvss_score DECIMAL(3,1),
    risk_score DECIMAL(3,1),
    severity VARCHAR(20),
    is_direct BOOLEAN,
    description TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);
```

### API 仕様
```yaml
# OpenAPI 3.0 仕様
paths:
  /api/v1/scans:
    post:
      summary: Submit scan results
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/ScanResult'
      responses:
        201:
          description: Scan result stored successfully
          
  /api/v1/orgs/{org}/dashboard:
    get:
      summary: Get organization dashboard data
      responses:
        200:
          description: Dashboard data
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/DashboardData'
```

## 📅 実装スケジュール

### Week 1-2: バックエンド基盤
- [ ] PostgreSQL スキーマ実装
- [ ] API サーバー基本構造
- [ ] 認証システム (GitHub OIDC)
- [ ] 基本的なCRUD API

### Week 3-4: API完成・テスト
- [ ] 全API エンドポイント実装
- [ ] データ集約ロジック
- [ ] 単体・統合テスト
- [ ] パフォーマンス最適化

### Week 5-6: フロントエンド開発
- [ ] Next.js プロジェクト初期化
- [ ] 認証フロー実装
- [ ] 組織ダッシュボード画面
- [ ] レスポンシブデザイン

### Week 7-8: 統合・最適化
- [ ] GitHub Actions統合拡張
- [ ] エンドツーエンドテスト
- [ ] パフォーマンス調整
- [ ] ドキュメント整備

## 🎯 成功指標

### 技術指標
- **API応答時間**: 95%ile で 500ms以内
- **ダッシュボード初期表示**: 2秒以内
- **同時接続数**: 1000ユーザー対応
- **データ更新頻度**: リアルタイム (WebSocket)

### ビジネス指標
- **組織カバレッジ**: 200リポジトリ × 30日履歴
- **ユーザビリティ**: 直感的な操作性
- **可視化効果**: リスクトレンドの明確化

## 🚀 次のアクション

どの部分から始めたいですか？

**A. データベース設計・実装**
- PostgreSQL スキーマ作成
- マイグレーション設定
- 基本的なモデル定義

**B. API サーバー基盤構築**
- Go Gin フレームワーク設定
- 認証システム実装
- 基本的なルーティング

**C. フロントエンド環境構築**
- Next.js プロジェクト初期化
- UI コンポーネント設計
- 認証フロー実装

推奨は **A → B → C** の順序ですが、お好みに合わせて調整可能です！