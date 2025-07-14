# Dep-Risk Dashboard

## 🎯 概要

Dep-Risk Dashboard は、組織レベルでの依存関係脆弱性を可視化するモダンなWebダッシュボードです。Next.js + TypeScript + Chakra UI で構築されています。

## ✨ 主な機能

### 📊 ダッシュボード概要
- **リアルタイム統計**: 平均リスクスコア、総リポジトリ数、脆弱性数
- **リスクトレンド**: 過去7日間のリスクスコア推移
- **リポジトリヒートマップ**: 各リポジトリのリスク状況を視覚化
- **脆弱性テーブル**: 詳細な脆弱性情報とソート・検索機能

### 🎨 UI/UX特徴
- **レスポンシブデザイン**: モバイル・タブレット・デスクトップ対応
- **リアルタイム更新**: SWRによる30秒間隔の自動更新
- **インタラクティブチャート**: Rechartsによる美しいデータ可視化
- **アクセシブル**: Chakra UIによる高いアクセシビリティ

## 🛠️ 技術スタック

- **フレームワーク**: Next.js 14 (App Router)
- **言語**: TypeScript
- **UIライブラリ**: Chakra UI v2
- **データフェッチング**: SWR + Axios
- **チャート**: Recharts
- **スタイリング**: Emotion (Chakra UI内蔵)

## 🚀 開発環境セットアップ

### 前提条件
- Node.js 18+ 
- npm または yarn
- Dep-Risk API サーバーが起動していること (localhost:8080)

### インストール・起動

```bash
# 依存関係のインストール
cd dashboard
npm install --legacy-peer-deps

# 開発サーバー起動
npm run dev

# ブラウザで http://localhost:3000 を開く
```

### 環境変数設定

`.env.local` ファイルを作成:

```bash
NEXT_PUBLIC_API_URL=http://localhost:8080
```

## 📁 プロジェクト構造

```
dashboard/
├── src/
│   ├── app/                 # Next.js App Router
│   │   ├── layout.tsx       # ルートレイアウト
│   │   └── page.tsx         # メインダッシュボード
│   ├── components/          # UIコンポーネント
│   │   ├── DashboardStats.tsx
│   │   ├── RiskTrendChart.tsx
│   │   ├── VulnerabilityTable.tsx
│   │   └── RepositoryHeatmap.tsx
│   ├── lib/                 # ユーティリティ
│   │   ├── api.ts           # API接続・SWRフック
│   │   └── chakra.tsx       # Chakra UIテーマ設定
│   └── types/               # TypeScript型定義
│       └── index.ts
├── next.config.js           # Next.js設定
├── tsconfig.json           # TypeScript設定
└── package.json            # 依存関係
```

## 🎨 コンポーネント詳細

### DashboardStats
- 4つの主要メトリクスを表示
- リスクレベル別の色分け
- リアルタイム更新対応

### RiskTrendChart
- 過去7日間のリスクスコア推移
- エリアチャート + ラインチャートの組み合わせ
- カスタムツールチップ

### VulnerabilityTable
- ソート・検索機能付きテーブル
- CVEリンク、パッケージ情報表示
- リスクレベル別バッジ

### RepositoryHeatmap
- リポジトリ別リスク状況
- プログレスバーによる視覚化
- トレンド矢印表示

## 🔧 カスタマイズ

### テーマ変更
`src/lib/chakra.tsx` でカラーテーマを変更可能:

```typescript
const theme = extendTheme({
  colors: {
    brand: {
      500: '#319795', // メインカラー
    },
    risk: {
      low: '#48BB78',    // 低リスク
      medium: '#ED8936', // 中リスク
      high: '#F56565',   // 高リスク
    }
  }
})
```

### API エンドポイント追加
`src/lib/api.ts` で新しいAPIフックを追加:

```typescript
export function useNewEndpoint(param: string) {
  const { data, error, isLoading } = useSWR(
    `${API_BASE_URL}/api/v1/new-endpoint/${param}`,
    fetcher
  )
  return { data, error, isLoading }
}
```

## 📊 データフロー

1. **SWR** が API からデータを取得
2. **コンポーネント** がデータを受け取り表示
3. **30秒間隔** で自動更新
4. **エラー時** は適切なフォールバック表示

## 🚀 本番デプロイ

```bash
# ビルド
npm run build

# 本番サーバー起動
npm start
```

### Vercel デプロイ
```bash
# Vercel CLI インストール
npm i -g vercel

# デプロイ
vercel --prod
```

## 🔮 今後の拡張予定

- **リアルタイム通知**: WebSocket統合
- **詳細ページ**: リポジトリ・脆弱性の詳細画面
- **エクスポート機能**: PDF・CSV出力
- **ダークモード**: テーマ切り替え
- **多言語対応**: i18n統合

---

**フロントエンドダッシュボードが完成しました！** 🎉

美しく実用的なダッシュボードで、組織の脆弱性状況を直感的に把握できます。