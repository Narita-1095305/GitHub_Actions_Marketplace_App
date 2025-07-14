package scorer

import (
	"testing"

	"github.com/dep-risk/dep-risk/internal/scanner"
)

func TestNewScorer(t *testing.T) {
	scorer := NewScorer()
	
	if scorer.Weights.CVSS != 0.5 {
		t.Errorf("Expected CVSS weight 0.5, got %f", scorer.Weights.CVSS)
	}
	
	if scorer.Weights.Popularity != 0.2 {
		t.Errorf("Expected Popularity weight 0.2, got %f", scorer.Weights.Popularity)
	}
}

func TestCalculateVulnerabilityScore(t *testing.T) {
	scorer := NewScorer()
	
	vuln := scanner.Vulnerability{
		ID:       "CVE-2023-1234",
		Package:  "test-package",
		Version:  "1.0.0",
		CVSS:     8.5,
		Severity: "HIGH",
		IsDirect: true,
	}
	
	score := scorer.CalculateVulnerabilityScore(vuln)
	
	if score.Overall < 0 || score.Overall > 10 {
		t.Errorf("Score should be between 0-10, got %f", score.Overall)
	}
	
	if score.CVSSComponent != 8.5 {
		t.Errorf("Expected CVSS component 8.5, got %f", score.CVSSComponent)
	}
	
	if score.Vulnerability.ID != vuln.ID {
		t.Errorf("Expected vulnerability ID %s, got %s", vuln.ID, score.Vulnerability.ID)
	}
}

func TestCalculateProjectScore(t *testing.T) {
	scorer := NewScorer()
	
	scanResult := &scanner.ScanResult{
		Vulnerabilities: []scanner.Vulnerability{
			{
				ID:       "CVE-2023-1234",
				Package:  "test-package",
				Version:  "1.0.0",
				CVSS:     8.5,
				Severity: "HIGH",
				IsDirect: true,
			},
			{
				ID:       "CVE-2023-5678",
				Package:  "another-package",
				Version:  "2.0.0",
				CVSS:     4.0,
				Severity: "MEDIUM",
				IsDirect: false,
			},
		},
		TotalCount: 2,
	}
	
	projectScore := scorer.CalculateProjectScore(scanResult)
	
	if projectScore.Summary.TotalVulnerabilities != 2 {
		t.Errorf("Expected 2 vulnerabilities, got %d", projectScore.Summary.TotalVulnerabilities)
	}
	
	if len(projectScore.VulnerabilityScores) != 2 {
		t.Errorf("Expected 2 vulnerability scores, got %d", len(projectScore.VulnerabilityScores))
	}
	
	if projectScore.OverallScore < 0 || projectScore.OverallScore > 10 {
		t.Errorf("Overall score should be between 0-10, got %f", projectScore.OverallScore)
	}
}

func TestDependencyComponent(t *testing.T) {
	scorer := NewScorer()
	
	// Direct dependency should have lower risk
	directScore := scorer.calculateDependencyComponent(true)
	transitiveScore := scorer.calculateDependencyComponent(false)
	
	if directScore >= transitiveScore {
		t.Errorf("Direct dependency should have lower risk than transitive. Direct: %f, Transitive: %f", 
			directScore, transitiveScore)
	}
}

func TestContextComponent(t *testing.T) {
	scorer := NewScorer()
	
	// Test high-risk package types
	httpVuln := scanner.Vulnerability{Package: "http-client"}
	cryptoVuln := scanner.Vulnerability{Package: "crypto-lib"}
	testVuln := scanner.Vulnerability{Package: "test-utils"}
	
	httpScore := scorer.calculateContextComponent(httpVuln)
	cryptoScore := scorer.calculateContextComponent(cryptoVuln)
	testScore := scorer.calculateContextComponent(testVuln)
	
	// HTTP and crypto should be higher risk than test utilities
	if httpScore <= testScore {
		t.Errorf("HTTP package should have higher risk than test package. HTTP: %f, Test: %f", 
			httpScore, testScore)
	}
	
	if cryptoScore <= testScore {
		t.Errorf("Crypto package should have higher risk than test package. Crypto: %f, Test: %f", 
			cryptoScore, testScore)
	}
}