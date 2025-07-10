# Risk Scoring Algorithm - 詳細設計

## 1. 概要

### 1.1 基本方針
- **透明性**: アルゴリズムの動作を開発者が理解できる
- **調整可能性**: 組織やプロジェクトに応じてパラメータを調整可能
- **実用性**: 実際のリスクを反映し、アクションにつながる
- **拡張性**: 新しい要素を追加しやすい設計

### 1.2 スコア範囲
- **0.0 - 10.0**: 小数点第1位まで
- **0.0 - 2.9**: 低リスク (緑)
- **3.0 - 6.9**: 中リスク (黄)
- **7.0 - 10.0**: 高リスク (赤)

## 2. 基本計算式

### 2.1 メイン計算式
```
Risk Score = min(10.0, 
  (CVSS Component × W1) + 
  (Popularity Component × W2) + 
  (Dependency Component × W3) + 
  (Context Component × W4) +
  Industry Modifier +
  Language Modifier
)

デフォルト重み:
W1 = 0.50 (CVSS)
W2 = 0.20 (Popularity)  
W3 = 0.15 (Dependency)
W4 = 0.15 (Context)
```

## 3. 各コンポーネントの詳細

### 3.1 CVSS Component (重み: 50%)

#### 3.1.1 基本CVSS変換
```go
func calculateCVSSComponent(cvss float64, severity string) float64 {
    // CVSS 0-10 を Risk Score 0-10 にマッピング
    baseScore := cvss
    
    // 重要度による補正
    severityMultiplier := map[string]float64{
        "CRITICAL": 1.2,
        "HIGH":     1.0,
        "MEDIUM":   0.8,
        "LOW":      0.6,
        "":         1.0, // 不明な場合
    }
    
    multiplier := severityMultiplier[strings.ToUpper(severity)]
    return min(10.0, baseScore * multiplier)
}
```

#### 3.1.2 CVSS v3.1 詳細スコアリング
```go
type CVSSv31 struct {
    BaseScore           float64
    TemporalScore       float64  // 時間的メトリクス
    EnvironmentalScore  float64  // 環境的メトリクス
    
    // Base Metrics
    AttackVector        string   // N/A/L/P (Network/Adjacent/Local/Physical)
    AttackComplexity    string   // L/H (Low/High)
    PrivilegesRequired  string   // N/L/H (None/Low/High)
    UserInteraction     string   // N/R (None/Required)
    Scope              string   // U/C (Unchanged/Changed)
    
    // Impact Metrics
    Confidentiality    string   // N/L/H (None/Low/High)
    Integrity          string   // N/L/H
    Availability       string   // N/L/H
}

func (c CVSSv31) calculateEnhancedScore() float64 {
    baseScore := c.BaseScore
    
    // Attack Vector による補正
    avMultiplier := map[string]float64{
        "NETWORK":  1.2,  // リモート攻撃可能
        "ADJACENT": 1.0,
        "LOCAL":    0.8,
        "PHYSICAL": 0.6,
    }
    
    // User Interaction による補正
    uiMultiplier := map[string]float64{
        "NONE":     1.1,  // ユーザー操作不要
        "REQUIRED": 0.9,
    }
    
    // Scope による補正
    scopeMultiplier := map[string]float64{
        "CHANGED":   1.15, // 影響範囲が拡大
        "UNCHANGED": 1.0,
    }
    
    score := baseScore
    score *= avMultiplier[c.AttackVector]
    score *= uiMultiplier[c.UserInteraction]
    score *= scopeMultiplier[c.Scope]
    
    return min(10.0, score)
}
```

### 3.2 Popularity Component (重み: 20%)

#### 3.2.1 パッケージ人気度の逆相関
```go
type PopularityMetrics struct {
    GitHubStars      int64
    NPMDownloads     int64  // 月間ダウンロード数
    PyPIDownloads    int64
    GoProxyDownloads int64
    Age              int    // パッケージの年数
    Contributors     int    // コントリビューター数
    LastUpdate       time.Time
}

func calculatePopularityComponent(metrics PopularityMetrics, ecosystem string) float64 {
    // エコシステム別の基準値
    thresholds := map[string]struct{
        HighPopularity int64
        MedPopularity  int64
    }{
        "npm": {
            HighPopularity: 1000000, // 月間100万DL以上
            MedPopularity:  10000,   // 月間1万DL以上
        },
        "go": {
            HighPopularity: 100000,  // 月間10万DL以上
            MedPopularity:  1000,    // 月間1000DL以上
        },
        "pypi": {
            HighPopularity: 500000,  // 月間50万DL以上
            MedPopularity:  5000,    // 月間5000DL以上
        },
    }
    
    threshold := thresholds[ecosystem]
    downloads := getDownloadsForEcosystem(metrics, ecosystem)
    
    var popularityScore float64
    
    switch {
    case downloads >= threshold.HighPopularity:
        popularityScore = 0.0  // 非常に人気 = 低リスク
    case downloads >= threshold.MedPopularity:
        popularityScore = 2.0  // 中程度の人気
    case downloads >= 100:
        popularityScore = 5.0  // 低い人気
    default:
        popularityScore = 8.0  // 非常に低い人気 = 高リスク
    }
    
    // 年数による補正（新しすぎるパッケージはリスク高）
    ageModifier := calculateAgeModifier(metrics.Age)
    
    // 最終更新による補正（古すぎるパッケージはリスク高）
    updateModifier := calculateUpdateModifier(metrics.LastUpdate)
    
    // コントリビューター数による補正
    contributorModifier := calculateContributorModifier(metrics.Contributors)
    
    finalScore := popularityScore + ageModifier + updateModifier + contributorModifier
    return max(0.0, min(10.0, finalScore))
}

func calculateAgeModifier(ageYears int) float64 {
    switch {
    case ageYears < 1:
        return 2.0  // 1年未満は高リスク
    case ageYears < 2:
        return 1.0  // 2年未満は中リスク
    case ageYears >= 5:
        return -0.5 // 5年以上は安定
    default:
        return 0.0
    }
}

func calculateUpdateModifier(lastUpdate time.Time) float64 {
    daysSinceUpdate := int(time.Since(lastUpdate).Hours() / 24)
    
    switch {
    case daysSinceUpdate > 730: // 2年以上更新なし
        return 3.0
    case daysSinceUpdate > 365: // 1年以上更新なし
        return 1.5
    case daysSinceUpdate > 180: // 6ヶ月以上更新なし
        return 0.5
    default:
        return 0.0
    }
}

func calculateContributorModifier(contributors int) float64 {
    switch {
    case contributors >= 50:
        return -0.5 // 多くのコントリビューター = 低リスク
    case contributors >= 10:
        return 0.0
    case contributors >= 3:
        return 0.5
    case contributors == 1:
        return 2.0  // 単一メンテナー = 高リスク
    default:
        return 1.0
    }
}
```

### 3.3 Dependency Component (重み: 15%)

#### 3.3.1 依存関係の深度とタイプ
```go
type DependencyInfo struct {
    IsDirectDependency    bool
    DepthFromRoot        int
    DependencyType       string // "production", "development", "optional"
    TransitiveDependents int    // このパッケージに依存するパッケージ数
    CyclicDependency     bool   // 循環依存の有無
}

func calculateDependencyComponent(depInfo DependencyInfo) float64 {
    baseScore := 0.0
    
    // 直接依存 vs 間接依存
    if depInfo.IsDirectDependency {
        baseScore = 6.0  // 直接依存は影響大
    } else {
        // 間接依存は深度に応じて影響度が下がる
        baseScore = max(1.0, 6.0 - float64(depInfo.DepthFromRoot) * 1.5)
    }
    
    // 依存タイプによる補正
    typeModifier := map[string]float64{
        "production":  1.0,
        "development": 0.3,  // 開発依存は影響小
        "optional":    0.5,  // オプション依存は影響中
        "peer":        0.8,  // ピア依存は影響中
    }
    
    if modifier, exists := typeModifier[depInfo.DependencyType]; exists {
        baseScore *= modifier
    }
    
    // 推移的依存数による補正（多くのパッケージがこれに依存している場合）
    if depInfo.TransitiveDependents > 10 {
        baseScore += 1.0  // 影響範囲が大きい
    }
    
    // 循環依存による補正
    if depInfo.CyclicDependency {
        baseScore += 2.0  // 循環依存は高リスク
    }
    
    return max(0.0, min(10.0, baseScore))
}
```

### 3.4 Context Component (重み: 15%)

#### 3.4.1 実行コンテキストとエクスポーズ
```go
type ContextInfo struct {
    ExecutionContext    []string // "server", "client", "cli", "library"
    NetworkExposed      bool     // ネットワークに公開されるか
    PrivilegedAccess    bool     // 特権アクセスが必要か
    DataSensitivity     string   // "public", "internal", "confidential", "secret"
    ComplianceRequired  []string // "SOX", "HIPAA", "GDPR", "PCI-DSS"
    Environment         string   // "production", "staging", "development"
}

func calculateContextComponent(contextInfo ContextInfo) float64 {
    baseScore := 3.0  // ベーススコア
    
    // 実行コンテキストによる補正
    for _, context := range contextInfo.ExecutionContext {
        switch context {
        case "server":
            baseScore += 2.0  // サーバーサイドは高リスク
        case "client":
            baseScore += 1.0  // クライアントサイドは中リスク
        case "cli":
            baseScore += 0.5  // CLIは低リスク
        case "library":
            baseScore += 1.5  // ライブラリは中〜高リスク
        }
    }
    
    // ネットワーク公開による補正
    if contextInfo.NetworkExposed {
        baseScore += 3.0
    }
    
    // 特権アクセスによる補正
    if contextInfo.PrivilegedAccess {
        baseScore += 2.0
    }
    
    // データ機密性による補正
    sensitivityModifier := map[string]float64{
        "public":       0.0,
        "internal":     0.5,
        "confidential": 1.5,
        "secret":       3.0,
    }
    
    if modifier, exists := sensitivityModifier[contextInfo.DataSensitivity]; exists {
        baseScore += modifier
    }
    
    // コンプライアンス要件による補正
    baseScore += float64(len(contextInfo.ComplianceRequired)) * 0.5
    
    // 環境による補正
    envModifier := map[string]float64{
        "production":  1.0,
        "staging":     0.7,
        "development": 0.3,
    }
    
    if modifier, exists := envModifier[contextInfo.Environment]; exists {
        baseScore *= modifier
    }
    
    return max(0.0, min(10.0, baseScore))
}
```

## 4. 業界別・言語別補正

### 4.1 業界別補正
```go
type IndustryModifier struct {
    Industry string
    Modifier float64
}

var industryModifiers = []IndustryModifier{
    {"finance", 1.5},        // 金融業界は高いセキュリティ要求
    {"healthcare", 1.3},     // 医療業界はHIPAA等の要求
    {"government", 1.4},     // 政府機関は高いセキュリティ要求
    {"education", 0.9},      // 教育機関は比較的寛容
    {"gaming", 0.8},         // ゲーム業界は比較的寛容
    {"ecommerce", 1.2},      // ECは決済情報を扱う
    {"media", 0.9},          // メディア業界は比較的寛容
    {"enterprise", 1.1},     // エンタープライズは中程度
    {"startup", 0.7},        // スタートアップは速度重視
}

func getIndustryModifier(industry string) float64 {
    for _, modifier := range industryModifiers {
        if modifier.Industry == industry {
            return modifier.Modifier
        }
    }
    return 1.0 // デフォルト
}
```

### 4.2 言語・エコシステム別補正
```go
type LanguageModifier struct {
    Language string
    Modifier float64
    Reason   string
}

var languageModifiers = []LanguageModifier{
    {"javascript", 1.2, "npm エコシステムの脆弱性が多い"},
    {"typescript", 1.1, "npm ベースだが型安全性がある"},
    {"python", 1.0, "標準的なリスクレベル"},
    {"go", 0.9, "比較的新しく、依存関係が少ない傾向"},
    {"rust", 0.8, "メモリ安全性とパッケージ管理が優秀"},
    {"java", 1.1, "大きなエコシステム、レガシーコードが多い"},
    {"c", 1.4, "メモリ安全性の問題が多い"},
    {"cpp", 1.3, "メモリ安全性の問題が多い"},
    {"php", 1.2, "歴史的にセキュリティ問題が多い"},
    {"ruby", 1.0, "標準的なリスクレベル"},
}

func getLanguageModifier(language string) float64 {
    for _, modifier := range languageModifiers {
        if modifier.Language == language {
            return modifier.Modifier
        }
    }
    return 1.0 // デフォルト
}
```

## 5. 動的重み調整

### 5.1 設定可能な重み
```yaml
# .github/dep-risk.yml
scoring:
  weights:
    cvss: 0.50
    popularity: 0.20
    dependency: 0.15
    context: 0.15
  
  modifiers:
    industry: "finance"  # 業界指定
    language_boost:      # 言語別ブースト
      javascript: 1.2
      python: 1.0
    
  custom_rules:
    - name: "Critical Infrastructure"
      condition: "context.network_exposed && context.privileged_access"
      modifier: 2.0
    
    - name: "Development Only"
      condition: "dependency.type == 'development'"
      modifier: 0.3
```

### 5.2 機械学習による重み最適化（将来拡張）
```go
type MLOptimizer struct {
    TrainingData []ScoringExample
    Model        *LinearRegression
}

type ScoringExample struct {
    Features      []float64  // CVSS, Popularity, etc.
    ActualImpact  float64    // 実際に問題になったかの評価
    FeedbackScore float64    // ユーザーからのフィードバック
}

func (ml *MLOptimizer) OptimizeWeights() ([]float64, error) {
    // 実際の脆弱性の影響度とスコアの相関を学習
    // ユーザーフィードバックを基に重みを調整
    // 定期的に重みを更新
}
```

## 6. スコア計算の実装例

### 6.1 メイン計算関数
```go
type RiskScorer struct {
    Config ScoringConfig
}

type ScoringConfig struct {
    Weights struct {
        CVSS       float64 `yaml:"cvss"`
        Popularity float64 `yaml:"popularity"`
        Dependency float64 `yaml:"dependency"`
        Context    float64 `yaml:"context"`
    } `yaml:"weights"`
    
    Industry string `yaml:"industry"`
    Language string `yaml:"language"`
}

func (rs *RiskScorer) CalculateRiskScore(vuln Vulnerability) float64 {
    // 各コンポーネントの計算
    cvssScore := rs.calculateCVSSComponent(vuln.CVSS)
    popularityScore := rs.calculatePopularityComponent(vuln.Package)
    dependencyScore := rs.calculateDependencyComponent(vuln.Dependency)
    contextScore := rs.calculateContextComponent(vuln.Context)
    
    // 重み付き合計
    baseScore := (cvssScore * rs.Config.Weights.CVSS) +
                (popularityScore * rs.Config.Weights.Popularity) +
                (dependencyScore * rs.Config.Weights.Dependency) +
                (contextScore * rs.Config.Weights.Context)
    
    // 業界・言語補正
    industryMod := getIndustryModifier(rs.Config.Industry)
    languageMod := getLanguageModifier(rs.Config.Language)
    
    finalScore := baseScore * industryMod * languageMod
    
    // 0-10の範囲に正規化
    return math.Max(0.0, math.Min(10.0, finalScore))
}
```

## 7. テストケースとバリデーション

### 7.1 テストケース例
```go
func TestRiskScoring(t *testing.T) {
    testCases := []struct {
        name     string
        vuln     Vulnerability
        expected float64
        tolerance float64
    }{
        {
            name: "Critical CVSS, Popular Package, Direct Dependency",
            vuln: Vulnerability{
                CVSS: CVSSv31{BaseScore: 9.8, Severity: "CRITICAL"},
                Package: Package{
                    NPMDownloads: 10000000, // 非常に人気
                    Age: 5,
                },
                Dependency: DependencyInfo{
                    IsDirectDependency: true,
                    DependencyType: "production",
                },
                Context: ContextInfo{
                    NetworkExposed: true,
                    Environment: "production",
                },
            },
            expected: 7.5, // 高CVSS だが人気パッケージなので少し下がる
            tolerance: 0.5,
        },
        {
            name: "Medium CVSS, Unpopular Package, Transitive Dependency",
            vuln: Vulnerability{
                CVSS: CVSSv31{BaseScore: 5.0, Severity: "MEDIUM"},
                Package: Package{
                    NPMDownloads: 100, // 非常に不人気
                    Age: 0.5, // 新しすぎる
                },
                Dependency: DependencyInfo{
                    IsDirectDependency: false,
                    DepthFromRoot: 3,
                    DependencyType: "production",
                },
                Context: ContextInfo{
                    NetworkExposed: false,
                    Environment: "development",
                },
            },
            expected: 4.2, // 中程度のCVSSだが不人気で新しいので上がる
            tolerance: 0.5,
        },
    }
    
    scorer := NewRiskScorer(DefaultScoringConfig())
    
    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            score := scorer.CalculateRiskScore(tc.vuln)
            if math.Abs(score - tc.expected) > tc.tolerance {
                t.Errorf("Expected %f ± %f, got %f", tc.expected, tc.tolerance, score)
            }
        })
    }
}
```

## 8. パフォーマンス最適化

### 8.1 キャッシュ戦略
```go
type ScoringCache struct {
    popularityCache map[string]PopularityMetrics
    cvssCache      map[string]CVSSv31
    mutex          sync.RWMutex
}

func (sc *ScoringCache) GetPopularityMetrics(packageName string) (PopularityMetrics, bool) {
    sc.mutex.RLock()
    defer sc.mutex.RUnlock()
    
    metrics, exists := sc.popularityCache[packageName]
    return metrics, exists
}
```

### 8.2 並列処理
```go
func (rs *RiskScorer) CalculateRiskScoresBatch(vulns []Vulnerability) []float64 {
    scores := make([]float64, len(vulns))
    
    // ワーカープールで並列処理
    const numWorkers = 10
    jobs := make(chan int, len(vulns))
    
    var wg sync.WaitGroup
    for i := 0; i < numWorkers; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for idx := range jobs {
                scores[idx] = rs.CalculateRiskScore(vulns[idx])
            }
        }()
    }
    
    for i := range vulns {
        jobs <- i
    }
    close(jobs)
    
    wg.Wait()
    return scores
}
```

## 9. 監視とメトリクス

### 9.1 スコアリング品質メトリクス
```go
type ScoringMetrics struct {
    TotalScored        int64
    HighRiskCount      int64
    MediumRiskCount    int64
    LowRiskCount       int64
    AverageScore       float64
    ScoringDuration    time.Duration
    CacheHitRate       float64
    FalsePositiveRate  float64  // ユーザーフィードバックから
    FalseNegativeRate  float64  // ユーザーフィードバックから
}
```

この詳細設計により、透明性があり調整可能で実用的なリスクスコアリングシステムを実装できます。