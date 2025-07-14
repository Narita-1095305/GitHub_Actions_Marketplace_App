package github

import (
	"strings"
	"testing"

	"github.com/dep-risk/dep-risk/internal/scanner"
	"github.com/dep-risk/dep-risk/internal/scorer"
)

func TestGetCommentTemplate(t *testing.T) {
	client := &Client{}
	
	// Test high risk
	highRiskScore := &scorer.ProjectRiskScore{
		OverallScore: 8.5,
	}
	template := client.getCommentTemplate(highRiskScore)
	if template.RiskLevel != "High Risk" {
		t.Errorf("Expected 'High Risk', got '%s'", template.RiskLevel)
	}
	if template.Emoji != "🚨" {
		t.Errorf("Expected '🚨', got '%s'", template.Emoji)
	}
	
	// Test medium risk
	mediumRiskScore := &scorer.ProjectRiskScore{
		OverallScore: 5.0,
	}
	template = client.getCommentTemplate(mediumRiskScore)
	if template.RiskLevel != "Medium Risk" {
		t.Errorf("Expected 'Medium Risk', got '%s'", template.RiskLevel)
	}
	
	// Test low risk
	lowRiskScore := &scorer.ProjectRiskScore{
		OverallScore: 2.0,
	}
	template = client.getCommentTemplate(lowRiskScore)
	if template.RiskLevel != "Low Risk" {
		t.Errorf("Expected 'Low Risk', got '%s'", template.RiskLevel)
	}
}

func TestDetermineConclusion(t *testing.T) {
	client := &Client{}
	
	// Test failure case
	conclusion := client.determineConclusion(8.0, 7.0)
	if conclusion != CheckRunConclusionFailure {
		t.Errorf("Expected failure conclusion for score above threshold")
	}
	
	// Test success case
	conclusion = client.determineConclusion(6.0, 7.0)
	if conclusion != CheckRunConclusionSuccess {
		t.Errorf("Expected success conclusion for score below threshold")
	}
}

func TestGenerateCommentBody(t *testing.T) {
	client := &Client{}
	
	projectScore := &scorer.ProjectRiskScore{
		OverallScore: 6.5,
		Summary: scorer.ScoreSummary{
			TotalVulnerabilities: 2,
			HighRiskCount:       1,
			MediumRiskCount:     1,
			LowRiskCount:        0,
			AverageScore:        6.5,
		},
		VulnerabilityScores: []scorer.RiskScore{
			{
				Overall: 8.0,
				Vulnerability: scanner.Vulnerability{
					ID:       "CVE-2023-1234",
					Package:  "test-package",
					Version:  "1.0.0",
					CVSS:     8.0,
					Severity: "HIGH",
				},
			},
		},
	}
	
	comment := client.generateCommentBody(projectScore)
	
	// Check that comment contains expected elements
	if !strings.Contains(comment, "dep-risk-comment") {
		t.Error("Comment should contain hidden marker")
	}
	
	if !strings.Contains(comment, "CVE-2023-1234") {
		t.Error("Comment should contain vulnerability ID")
	}
	
	if !strings.Contains(comment, "6.5/10") {
		t.Error("Comment should contain overall score")
	}
	
	if !strings.Contains(comment, "test-package") {
		t.Error("Comment should contain package name")
	}
}