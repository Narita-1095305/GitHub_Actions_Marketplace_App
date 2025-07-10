## GitHub Actions Marketplace App ― “Dep-Risk”

*(依存ライブラリ脆弱性スコアリング & ダッシュボード)*

---

### 1. 誰向けか (Personas)

| Persona             | 典型的な状況                    | このアプリで得たい価値                    |
| ------------------- | ------------------------- | ------------------------------ |
| **開発者**             | PR を出すたびに `go test` だけ実行中 | “脆弱パッケージが混ざったら CI が落ちて教えてくれる”  |
| **Tech Lead / SRE** | 20 以上のマイクロサービスを保守         | “どのリポが一番リスク高いか一目で把握したい”        |
| **セキュリティ担当**        | Dependabot＋手動監査を併用        | “全リポジトリの CVE 状況を 1 つの画面に集約したい” |
| **OSS メンテナ**        | 外部コントリビュータ PR を多数受け入れ     | “悪意あるパッケージ追加を自動ブロックしたい”        |

---

### 2. 主なユースケース

| UC-ID              | トリガー                      | フロー                                                    | 成果物                                 |
| ------------------ | ------------------------- | ------------------------------------------------------ | ----------------------------------- |
| **UC-1** PR スキャン   | `pull_request`            | Action が SBOM → CVE スキャン → **PR コメント** + **Check-run** | 危険スコア ≥ 7 で CI 失敗、マージ不可             |
| **UC-2** 定期ヘルスチェック | `schedule` (毎晩)           | 各リポを走査 → 結果をバックエンドへ集約                                  | **Dashboard Heatmap** 更新 & Slack 通知 |
| **UC-3** 組織レポート    | 手動                        | Dashboard から CSV/PNG エクスポート                            | 月次レビュー資料に貼り付け                       |
| **UC-4** ポリシー運用    | `.github/dep-risk.yml` 変更 | しきい値 / 無視リストを YAML で宣言                                 | コードレビューでポリシー差分が見える                  |

---

### 3. 使用方法（最小ステップ）

1. **GitHub Marketplace で “Dep-Risk” を Install**

   * Org 全体 or 個別 Repo を選択

2. **ワークフローに 2 行追加**

   ```yaml
   - uses: org/dep-risk@v1
     with:
       fail_threshold: 7
   ```

3. **PR を作成** → Bot がコメント例を投稿し、基準超過なら CI ❌

4. **サイト or GitHub App タブ**でヒートマップを確認
   （例: `https://app.deprisk.io/org/<org-slug>`）

---

### 4. ざっくり要件 (MVP)

| 区分            | 必須                                                     | 補足                           |
| ------------- | ------------------------------------------------------ | ---------------------------- |
| **入力**        | `go.sum`, `package-lock.json` を自動検出                    | マルチ言語化は Nice-to-have         |
| **検出エンジン**    | syft で SBOM → osv-scanner で CVE 照合                     | オフライン DB 更新は日次               |
| **スコア算定**     | CVSS + Package Popularity で 0–10                       | 重みは JSON で調整可                |
| **CI 出力**     | PR コメント＋Check-run 失敗／成功                                | SARIF をアップロードし Security タブ統合 |
| **集約 API**    | Go + Postgres、リクエスト認可は GitHub PAT/OIDC                 | 組織/Repo/日付キーで集計              |
| **Dashboard** | Next.js + Chakra UI (Heatmap・テーブル)                     | 200 Repo × 30 日でも < 1 s 表示   |
| **デプロイ**      | Docker Action イメージ (distroless)／Backend on AWS Fargate | CLI 実行はメモリ ≤ 1 GB / 30 s     |
| **セキュリティ**    | Cosign 署名、OIDC トークン限定スコープ                              | 個人データは保持しない                  |

