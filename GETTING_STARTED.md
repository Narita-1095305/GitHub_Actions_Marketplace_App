# 🚀 Dep-Risk 使い方ガイド（初心者向け）

## 📖 Dep-Riskとは？

**Dep-Risk**は、あなたのプロジェクトの依存関係（ライブラリ）に潜む脆弱性を自動で検出し、リスクスコアを計算してくれるツールです。

### 🎯 何ができるの？
- ✅ **自動脆弱性検出**: プロジェクトの依存関係をスキャンして危険なライブラリを発見
- ✅ **リスクスコア計算**: 0-10のスコアで危険度を数値化
- ✅ **GitHub統合**: プルリクエストに自動コメント、セキュリティタブに結果表示
- ✅ **CI/CD統合**: 危険度が高い場合はビルドを失敗させて安全性を確保

---

## 🏃‍♂️ 5分でできる！クイックスタート

### ステップ1: GitHubリポジトリに設定ファイルを追加

あなたのプロジェクトのルートディレクトリに `.github/workflows/security.yml` ファイルを作成します：

```yaml
name: セキュリティスキャン

# いつ実行するか
on:
  pull_request:    # プルリクエスト時
  push:
    branches: [main]  # mainブランチへのプッシュ時

jobs:
  security:
    runs-on: ubuntu-latest
    
    # 必要な権限
    permissions:
      contents: read
      pull-requests: write
      security-events: write
      checks: write
    
    steps:
    - name: コードをチェックアウト
      uses: actions/checkout@v4
    
    - name: Dep-Riskでセキュリティスキャン
      uses: dep-risk/dep-risk@v1
      with:
        fail_threshold: 7.0    # 7.0以上で失敗
        warn_threshold: 3.0    # 3.0以上で警告
        github_token: ${{ secrets.GITHUB_TOKEN }}
```

### ステップ2: 設定完了！

これだけです！次回プルリクエストを作成すると、自動でセキュリティスキャンが実行されます。

---

## 📊 実際の動作例

### スキャン実行時の出力例
```
🔍 Starting vulnerability scan...
📊 Found 3 vulnerabilities
⚖️  Calculating risk scores...

📋 Scan Summary:
   Overall Risk Score: 6.5/10
   Total Vulnerabilities: 3
   High Risk: 1 | Medium Risk: 1 | Low Risk: 1

🔍 Top Vulnerabilities:
   • CVE-2023-1234 in express v4.17.1 (Score: 8.2, CVSS: 8.5)
   • CVE-2023-5678 in lodash v4.17.20 (Score: 4.8, CVSS: 4.3)

✅ Scan passed: Risk score 6.5 is below threshold 7.0
```

### プルリクエストでの表示
- 🟢 **成功時**: 「✅ セキュリティスキャン通過」
- 🟡 **警告時**: 「⚠️ 軽微な脆弱性が見つかりました」
- 🔴 **失敗時**: 「❌ 高リスクな脆弱性が検出されました」

---

## ⚙️ カスタマイズ設定

### 基本設定（推奨）

`.github/dep-risk.yml` ファイルを作成して、詳細設定をカスタマイズできます：

```yaml
# 基本的な閾値設定
fail_threshold: 7.0    # この値以上でCI失敗
warn_threshold: 3.0    # この値以上で警告表示

# リスクスコア計算の重み（合計1.0になるように）
cvss_weight: 0.5          # 脆弱性の深刻度 (50%)
popularity_weight: 0.2    # パッケージの人気度 (20%)
dependency_weight: 0.15   # 依存関係の種類 (15%)
context_weight: 0.15      # 使用コンテキスト (15%)

# 出力設定
comment_mode: "on-failure"  # PRコメント: always, on-failure, never
sarif_upload: true          # GitHubセキュリティタブに結果表示

# 無視リスト（必要に応じて）
ignore_list:
  - "CVE-2023-1234"  # 特定のCVEを無視
```

### 高度な設定例

```yaml
name: 高度なセキュリティスキャン

on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: '0 2 * * *'  # 毎日午前2時に実行

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      security-events: write
      checks: write
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Dep-Riskスキャン
      uses: dep-risk/dep-risk@v1
      with:
        fail_threshold: 8.0
        warn_threshold: 4.0
        languages: auto              # 自動検出
        exclude_paths: 'test,docs'   # 除外パス
        timeout: 300                 # タイムアウト（秒）
        parallel_jobs: 4             # 並列実行数
        cache_enabled: true          # キャッシュ有効
        github_token: ${{ secrets.GITHUB_TOKEN }}
    
    # 結果をアーティファクトとして保存
    - name: 結果を保存
      if: always()
      uses: actions/upload-artifact@v4
      with:
        name: security-report
        path: |
          dep-risk-report.json
          dep-risk.sarif
```

---

## 🎯 対応プロジェクト

### 自動検出される言語・ファイル
- **Go**: `go.mod`, `go.sum`
- **Node.js**: `package.json`, `package-lock.json`
- **Python**: `requirements.txt`, `Pipfile.lock` (近日対応)
- **Java**: `pom.xml`, `gradle.lock` (近日対応)

### プロジェクト例
```
your-project/
├── .github/
│   ├── workflows/
│   │   └── security.yml     # ← ここに設定
│   └── dep-risk.yml         # ← オプション設定
├── package.json             # Node.jsプロジェクト
├── go.mod                   # Goプロジェクト
└── src/
```

---

## 🔧 ローカルでのテスト

### 1. 必要なツールをインストール
```bash
# macOSの場合
brew install syft osv-scanner

# Linuxの場合
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh
go install github.com/google/osv-scanner/cmd/osv-scanner@latest
```

### 2. Dep-Riskをビルド
```bash
git clone https://github.com/your-org/dep-risk.git
cd dep-risk
go build -o dep-risk-cli ./cmd/action
```

### 3. プロジェクトをスキャン
```bash
cd your-project
../dep-risk/dep-risk-cli
```

---

## 🚨 トラブルシューティング

### よくある問題と解決方法

#### ❌ 「権限が不足しています」エラー
**解決方法**: ワークフローファイルに必要な権限を追加
```yaml
permissions:
  contents: read
  pull-requests: write
  security-events: write
  checks: write
```

#### ❌ 「スキャンがタイムアウトしました」エラー
**解決方法**: タイムアウト時間を延長
```yaml
with:
  timeout: 600  # 10分に延長
```

#### ❌ 「依存関係ファイルが見つかりません」エラー
**解決方法**: スキャンパスを明示的に指定
```yaml
with:
  scan_paths: './src,./lib'
```

#### ⚠️ 「誤検知が多すぎます」
**解決方法**: 閾値を調整または特定のCVEを無視
```yaml
# .github/dep-risk.yml
fail_threshold: 8.0  # より厳しく
ignore_list:
  - "CVE-2023-1234"  # 誤検知を無視
```

---

## 📊 ダッシュボード機能（オプション）

### Webダッシュボードの起動

#### 1. バックエンドAPI起動
```bash
# データベースを起動（Docker必要）
docker-compose up -d

# APIサーバーを起動
cd dep-risk
go build -o dep-risk-api ./cmd/api
./dep-risk-api
```

#### 2. フロントエンド起動
```bash
# 別のターミナルで
cd dashboard
npm install
npm run dev
```

#### 3. ダッシュボードにアクセス
ブラウザで `http://localhost:3000` にアクセスすると、以下が確認できます：

**📊 メイン画面**
- 組織全体のリスクスコア平均
- 総リポジトリ数と脆弱性数
- 最新スキャン日時
- 高リスクリポジトリ数

**🎯 リポジトリヒートマップ**
- 各リポジトリのリスクレベルを色分け表示
- 🔴 高リスク (7.0+) / 🟡 中リスク (3.0-7.0) / 🟢 低リスク (3.0未満)
- クリックで詳細情報表示

**📈 リスクトレンド**
- 時系列でのリスクスコア変化
- 脆弱性数の推移
- 改善・悪化の傾向分析

**🔍 脆弱性詳細テーブル**
- CVE ID、パッケージ名、バージョン
- リスクスコアとCVSSスコア
- 直接/間接依存関係の区別
- 修正バージョン情報

---

## 🎓 次のステップ

### 1. チーム導入
- 組織の全リポジトリに設定を展開
- チーム向けの閾値ポリシーを策定
- 定期的なセキュリティレビューを実施

### 2. 高度な活用
- Slackやメール通知の設定
- 月次セキュリティレポートの自動生成
- カスタムスコアリングルールの作成

### 3. 継続的改善
- 脆弱性対応プロセスの確立
- セキュリティ意識向上の取り組み
- 最新の脅威情報への対応

---

## 🆘 サポート

### 困ったときは
- 📖 [詳細ドキュメント](./README.md)
- 🐛 [Issue報告](https://github.com/your-org/dep-risk/issues)
- 💬 [ディスカッション](https://github.com/your-org/dep-risk/discussions)
- 📧 [メールサポート](mailto:support@deprisk.io)

### コミュニティ
- 🌟 GitHubでスターをつけて応援
- 🤝 改善提案やバグ報告を歓迎
- 📢 使用事例をシェア

---

**🎉 これで準備完了！安全で信頼性の高いソフトウェア開発を始めましょう！**