package scorer

import (
	"math"
	"strings"

	"github.com/dep-risk/dep-risk/internal/scanner"
)

// ScoringWeights defines the weights for different risk factors
type ScoringWeights struct {
	CVSS       float64 `json:"cvss" yaml:"cvss"`
	Popularity float64 `json:"popularity" yaml:"popularity"`
	Dependency float64 `json:"dependency" yaml:"dependency"`
	Context    float64 `json:"context" yaml:"context"`
}

// DefaultWeights returns the default scoring weights
func DefaultWeights() ScoringWeights {
	return ScoringWeights{
		CVSS:       0.5,
		Popularity: 0.2,
		Dependency: 0.15,
		Context:    0.15,
	}
}

// PackagePopularity represents popularity metrics for a package
type PackagePopularity struct {
	GitHubStars      int `json:"github_stars"`
	DownloadsPerMonth int `json:"downloads_per_month"`
	Age              int `json:"age_months"`
}

// RiskScore represents the calculated risk score for a vulnerability
type RiskScore struct {
	Overall          float64 `json:"overall"`
	CVSSComponent    float64 `json:"cvss_component"`
	PopularityComponent float64 `json:"popularity_component"`
	DependencyComponent float64 `json:"dependency_component"`
	ContextComponent    float64 `json:"context_component"`
	Vulnerability    scanner.Vulnerability `json:"vulnerability"`
}

// ProjectRiskScore represents the overall risk score for a project
type ProjectRiskScore struct {
	OverallScore     float64     `json:"overall_score"`
	MaxScore         float64     `json:"max_score"`
	VulnerabilityScores []RiskScore `json:"vulnerability_scores"`
	Summary          ScoreSummary `json:"summary"`
}

// ScoreSummary provides a summary of risk scores
type ScoreSummary struct {
	TotalVulnerabilities int     `json:"total_vulnerabilities"`
	HighRiskCount       int     `json:"high_risk_count"`
	MediumRiskCount     int     `json:"medium_risk_count"`
	LowRiskCount        int     `json:"low_risk_count"`
	AverageScore        float64 `json:"average_score"`
}

// Scorer handles risk score calculations
type Scorer struct {
	Weights ScoringWeights
}

// NewScorer creates a new scorer with default weights
func NewScorer() *Scorer {
	return &Scorer{
		Weights: DefaultWeights(),
	}
}

// NewScorerWithWeights creates a new scorer with custom weights
func NewScorerWithWeights(weights ScoringWeights) *Scorer {
	return &Scorer{
		Weights: weights,
	}
}

// CalculateProjectScore calculates the overall risk score for a project
func (s *Scorer) CalculateProjectScore(scanResult *scanner.ScanResult) *ProjectRiskScore {
	var vulnerabilityScores []RiskScore
	var totalScore float64
	var maxScore float64

	for _, vuln := range scanResult.Vulnerabilities {
		score := s.CalculateVulnerabilityScore(vuln)
		vulnerabilityScores = append(vulnerabilityScores, score)
		
		// Use weighted average for overall score
		totalScore += score.Overall
		if score.Overall > maxScore {
			maxScore = score.Overall
		}
	}

	var overallScore float64
	if len(vulnerabilityScores) > 0 {
		// Use the maximum score as the project risk score
		// This ensures that even one high-risk vulnerability makes the project high-risk
		overallScore = maxScore
	}

	summary := s.calculateSummary(vulnerabilityScores)

	return &ProjectRiskScore{
		OverallScore:        overallScore,
		MaxScore:           maxScore,
		VulnerabilityScores: vulnerabilityScores,
		Summary:            summary,
	}
}

// CalculateVulnerabilityScore calculates the risk score for a single vulnerability
func (s *Scorer) CalculateVulnerabilityScore(vuln scanner.Vulnerability) RiskScore {
	// Calculate CVSS component (0-10 scale)
	cvssComponent := s.calculateCVSSComponent(vuln.CVSS)
	
	// Calculate popularity component (0-10 scale)
	popularityComponent := s.calculatePopularityComponent(vuln.Package)
	
	// Calculate dependency component (0-10 scale)
	dependencyComponent := s.calculateDependencyComponent(vuln.IsDirect)
	
	// Calculate context component (0-10 scale)
	contextComponent := s.calculateContextComponent(vuln)
	
	// Calculate weighted overall score
	overall := (cvssComponent * s.Weights.CVSS) +
		(popularityComponent * s.Weights.Popularity) +
		(dependencyComponent * s.Weights.Dependency) +
		(contextComponent * s.Weights.Context)
	
	// Ensure score is within 0-10 range
	overall = math.Max(0, math.Min(10, overall))
	
	return RiskScore{
		Overall:             overall,
		CVSSComponent:       cvssComponent,
		PopularityComponent: popularityComponent,
		DependencyComponent: dependencyComponent,
		ContextComponent:    contextComponent,
		Vulnerability:       vuln,
	}
}

// calculateCVSSComponent calculates the CVSS-based component of the risk score
func (s *Scorer) calculateCVSSComponent(cvss float64) float64 {
	// CVSS is already on a 0-10 scale
	return cvss
}

// calculatePopularityComponent calculates the popularity-based component
func (s *Scorer) calculatePopularityComponent(packageName string) float64 {
	// For MVP, we'll use a simplified popularity calculation
	// In a full implementation, this would query package registries
	
	popularity := s.getPackagePopularity(packageName)
	
	// Calculate popularity factor: less popular packages are riskier
	// Formula: max(0, 10 - log10(downloads_per_month / 1000))
	if popularity.DownloadsPerMonth > 0 {
		factor := math.Log10(float64(popularity.DownloadsPerMonth) / 1000.0)
		return math.Max(0, math.Min(10, 10-factor))
	}
	
	// Default to medium risk for unknown packages
	return 5.0
}

// calculateDependencyComponent calculates the dependency depth component
func (s *Scorer) calculateDependencyComponent(isDirect bool) float64 {
	// Direct dependencies are easier to update, so lower risk
	if isDirect {
		return 2.0
	}
	// Transitive dependencies are harder to control, so higher risk
	return 6.0
}

// calculateContextComponent calculates the context-based component
func (s *Scorer) calculateContextComponent(vuln scanner.Vulnerability) float64 {
	score := 5.0 // Base score
	
	// Increase risk for certain package types
	packageName := strings.ToLower(vuln.Package)
	
	// Network/HTTP libraries are higher risk
	if strings.Contains(packageName, "http") || 
	   strings.Contains(packageName, "net") ||
	   strings.Contains(packageName, "curl") ||
	   strings.Contains(packageName, "request") {
		score += 2.0
	}
	
	// Crypto libraries are higher risk
	if strings.Contains(packageName, "crypto") ||
	   strings.Contains(packageName, "ssl") ||
	   strings.Contains(packageName, "tls") {
		score += 1.5
	}
	
	// Authentication/authorization libraries are higher risk
	if strings.Contains(packageName, "auth") ||
	   strings.Contains(packageName, "jwt") ||
	   strings.Contains(packageName, "oauth") {
		score += 1.5
	}
	
	// Database libraries are medium-high risk
	if strings.Contains(packageName, "sql") ||
	   strings.Contains(packageName, "db") ||
	   strings.Contains(packageName, "mongo") ||
	   strings.Contains(packageName, "redis") {
		score += 1.0
	}
	
	// Development/testing tools are lower risk
	if strings.Contains(packageName, "test") ||
	   strings.Contains(packageName, "mock") ||
	   strings.Contains(packageName, "dev") {
		score -= 2.0
	}
	
	return math.Max(0, math.Min(10, score))
}

// getPackagePopularity retrieves popularity metrics for a package
func (s *Scorer) getPackagePopularity(packageName string) PackagePopularity {
	// For MVP, return mock data based on common packages
	// In a full implementation, this would query package registries
	
	commonPackages := map[string]PackagePopularity{
		"lodash":     {GitHubStars: 50000, DownloadsPerMonth: 50000000, Age: 120},
		"express":    {GitHubStars: 60000, DownloadsPerMonth: 20000000, Age: 144},
		"react":      {GitHubStars: 200000, DownloadsPerMonth: 15000000, Age: 108},
		"jquery":     {GitHubStars: 58000, DownloadsPerMonth: 8000000, Age: 180},
		"axios":      {GitHubStars: 100000, DownloadsPerMonth: 25000000, Age: 84},
		"moment":     {GitHubStars: 47000, DownloadsPerMonth: 12000000, Age: 132},
		"underscore": {GitHubStars: 27000, DownloadsPerMonth: 5000000, Age: 156},
	}
	
	if popularity, exists := commonPackages[packageName]; exists {
		return popularity
	}
	
	// Default values for unknown packages
	return PackagePopularity{
		GitHubStars:      1000,
		DownloadsPerMonth: 10000,
		Age:              24,
	}
}

// calculateSummary calculates summary statistics for vulnerability scores
func (s *Scorer) calculateSummary(scores []RiskScore) ScoreSummary {
	summary := ScoreSummary{
		TotalVulnerabilities: len(scores),
	}
	
	if len(scores) == 0 {
		return summary
	}
	
	var totalScore float64
	for _, score := range scores {
		totalScore += score.Overall
		
		// Categorize by risk level
		if score.Overall >= 7.0 {
			summary.HighRiskCount++
		} else if score.Overall >= 4.0 {
			summary.MediumRiskCount++
		} else {
			summary.LowRiskCount++
		}
	}
	
	summary.AverageScore = totalScore / float64(len(scores))
	
	return summary
}