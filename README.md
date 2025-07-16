# Dep-Risk: 依存関係リスク評価ツール

[![CI Status](https://github.com/rikiya-narita/GitHub_Actions_Marketplace_App/actions/workflows/ci.yml/badge.svg)](https://github.com/rikiya-narita/GitHub_Actions_Marketplace_App/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Dep-Risk** は、ソフトウェアプロジェクトの依存関係に潜む脆弱性を自動で検出し、実用的なリスクスコアを算出するためのGitHub Actionsアプリケーションです。CI/CDパイプラインに統合することで、開発の早い段階でセキュリティリスクを特定し、修正を促します。

![Dashboard Screenshot](https://user-images.githubusercontent.com/XXXXX/YYYYY.png) *(ここにダッシュボードのスクリーンショットを後で追加)*

## ✨ 主な機能

- **高精度な脆弱性スキャン**:
  - `syft` を利用してソフトウェア部品表 (SBOM) を生成し、`osv-scanner` を通じて包括的な脆弱性データベース (OSV, NVD) と照合します。
  - Go, Node.js, Python, Javaなど、主要なプログラミング言語に対応しています。

- **独自のインテリジェントなリスクスコアリング**:
  - 単純なCVSSスコアだけでなく、**パッケージの人気度**（GitHub Stars, ダウンロード数）、**依存関係の深さ**、**利用コンテキスト**などを多角的に分析し、0.0から10.0までの実用的なリスクスコアを算出します。
  - これにより、対応すべき脆弱性の優先順位付けが容易になります。

- **シームレスなGitHub統合**:
  - **プルリクエストへのコメント**: 新たな脆弱性が検知されると、PRに詳細なレポートと修正案を自動でコメントします。
  - **Check-Runs連携**: 設定したリスクしきい値を超えた場合にCIを失敗させ、危険なコードのマージを未然に防ぎます。
  - **Securityタブ連携**: スキャン結果をSARIF形式で出力し、GitHubのSecurityタブに脆弱性を表示します。

- **一元管理ダッシュボード**:
  - 組織内の全リポジトリのリスク状況を可視化するWebダッシュボードを提供します。
  - リスクの高いリポジトリや、時間経過によるリスクの変化を直感的に把握できます。

## ⚙️ 設定

より詳細な設定は、リポジトリのルートに `.github/dep-risk.yml` を作成することで可能です。

```yaml
# .github/dep-risk.yml

# スコアリングの重み付けをカスタマイズ
scoring:
  weights:
    cvss: 0.5
    popularity: 0.2
    dependency: 0.15
    context: 0.15

# 無視する脆弱性やパッケージを指定
ignore:
  # CVE-IDで指定
  cves:
    - 'CVE-2021-44228'
  # パッケージ名とバージョンで指定 (semver形式が利用可能)
  packages:
    - name: 'lodash'
      version: '< 4.17.21'
      reason: '社内ライブラリとの互換性問題のため、次四半期に対応予定'
      expires: '2025-10-01'
  # 特定のパスをスキャン対象から除外
  paths:
    - 'test/**'
    - 'docs/**'

# PRコメントの投稿モード (always, on-failure, never)
output:
  comment:
    mode: 'on-failure'
```

詳細な設定項目については、[ドキュメント](https://github.com/rikiya-narita/GitHub_Actions_Marketplace_App/wiki) *(Wikiは後で作成)* を参照してください。

## 🛠️ ローカルでの実行

開発やデバッグのために、CLIツールをローカルで実行することも可能です。

```bash
# 依存関係のインストール
go mod tidy

# ビルド
go build -o dep-risk ./cmd/action

# 実行 (スキャン対象のディレクトリを指定)
./dep-risk --path /path/to/your/project
```

## 📚 ドキュメント

- 🚀 **[初心者向けガイド](./GETTING_STARTED.md)** - 5分で始められる詳しい使い方
- 📖 **[詳細仕様書](./detailed_requirements_and_design.md)** - 技術的な詳細情報
- 🧮 **[リスクスコア算定](./risk_scoring_algorithm_detailed.md)** - スコア計算の仕組み
- 🔧 **[CLI/APIリファレンス](./dep-risk/README.md)** - 開発者向け情報

## 🎯 クイックスタート

初めて使用する方は **[GETTING_STARTED.md](./GETTING_STARTED.md)** をご覧ください。5分でセットアップが完了します！

```yaml
# .github/workflows/security.yml
- uses: dep-risk/dep-risk@v1
  with:
    fail_threshold: 7.0
    github_token: ${{ secrets.GITHUB_TOKEN }}
```