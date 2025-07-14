package github

import (
	"context"
	"fmt"
	"time"

	"github.com/google/go-github/v57/github"
	"github.com/dep-risk/dep-risk/internal/scorer"
)

// CheckRunStatus represents the status of a check run
type CheckRunStatus string

const (
	CheckRunStatusQueued     CheckRunStatus = "queued"
	CheckRunStatusInProgress CheckRunStatus = "in_progress"
	CheckRunStatusCompleted  CheckRunStatus = "completed"
)

// CheckRunConclusion represents the conclusion of a check run
type CheckRunConclusion string

const (
	CheckRunConclusionSuccess        CheckRunConclusion = "success"
	CheckRunConclusionFailure        CheckRunConclusion = "failure"
	CheckRunConclusionNeutral        CheckRunConclusion = "neutral"
	CheckRunConclusionCancelled      CheckRunConclusion = "cancelled"
	CheckRunConclusionTimedOut       CheckRunConclusion = "timed_out"
	CheckRunConclusionActionRequired CheckRunConclusion = "action_required"
)

// CreateCheckRun creates a GitHub Check Run for the scan results
func (c *Client) CreateCheckRun(ctx context.Context, projectScore *scorer.ProjectRiskScore, failThreshold float64) error {
	checkRun := c.buildCheckRun(projectScore, failThreshold)
	
	_, _, err := c.client.Checks.CreateCheckRun(ctx, c.owner, c.repo, checkRun)
	if err != nil {
		return fmt.Errorf("failed to create check run: %w", err)
	}
	
	return nil
}

// buildCheckRun constructs the check run object
func (c *Client) buildCheckRun(projectScore *scorer.ProjectRiskScore, failThreshold float64) github.CreateCheckRunOptions {
	status := string(CheckRunStatusCompleted)
	conclusion := c.determineConclusion(projectScore.OverallScore, failThreshold)
	
	checkRun := github.CreateCheckRunOptions{
		Name:    "Dep-Risk Security Scan",
		HeadSHA: c.sha,
		Status:  &status,
	}
	
	// Set conclusion for completed check runs
	conclusionStr := string(conclusion)
	checkRun.Conclusion = &conclusionStr
	
	// Set timestamps
	now := github.Timestamp{Time: time.Now()}
	checkRun.StartedAt = &now
	checkRun.CompletedAt = &now
	
	// Build output
	output := c.buildCheckRunOutput(projectScore, failThreshold, conclusion)
	checkRun.Output = &output
	
	// Add actions for failed checks
	if conclusion == CheckRunConclusionFailure {
		checkRun.Actions = c.buildCheckRunActions()
	}
	
	return checkRun
}

// determineConclusion determines the check run conclusion based on risk score
func (c *Client) determineConclusion(riskScore, failThreshold float64) CheckRunConclusion {
	if riskScore >= failThreshold {
		return CheckRunConclusionFailure
	}
	return CheckRunConclusionSuccess
}

// buildCheckRunOutput creates the detailed output for the check run
func (c *Client) buildCheckRunOutput(projectScore *scorer.ProjectRiskScore, failThreshold float64, conclusion CheckRunConclusion) github.CheckRunOutput {
	title := c.buildOutputTitle(projectScore, conclusion)
	summary := c.buildOutputSummary(projectScore, failThreshold)
	text := c.buildOutputText(projectScore)
	
	return github.CheckRunOutput{
		Title:   &title,
		Summary: &summary,
		Text:    &text,
	}
}

// buildOutputTitle creates the title for the check run output
func (c *Client) buildOutputTitle(projectScore *scorer.ProjectRiskScore, conclusion CheckRunConclusion) string {
	switch conclusion {
	case CheckRunConclusionSuccess:
		if projectScore.Summary.TotalVulnerabilities == 0 {
			return "✅ No vulnerabilities found"
		}
		return fmt.Sprintf("✅ Risk score %.1f/10 - Below threshold", projectScore.OverallScore)
	case CheckRunConclusionFailure:
		return fmt.Sprintf("❌ Risk score %.1f/10 - Above threshold", projectScore.OverallScore)
	default:
		return "🔍 Security scan completed"
	}
}

// buildOutputSummary creates the summary for the check run output
func (c *Client) buildOutputSummary(projectScore *scorer.ProjectRiskScore, failThreshold float64) string {
	summary := fmt.Sprintf("**Risk Score**: %.1f/10 (Threshold: %.1f)\n", 
		projectScore.OverallScore, failThreshold)
	
	if projectScore.Summary.TotalVulnerabilities > 0 {
		summary += fmt.Sprintf("**Vulnerabilities Found**: %d total\n", 
			projectScore.Summary.TotalVulnerabilities)
		summary += fmt.Sprintf("- High Risk: %d\n", projectScore.Summary.HighRiskCount)
		summary += fmt.Sprintf("- Medium Risk: %d\n", projectScore.Summary.MediumRiskCount)
		summary += fmt.Sprintf("- Low Risk: %d\n", projectScore.Summary.LowRiskCount)
	} else {
		summary += "**No vulnerabilities detected** in your dependencies.\n"
	}
	
	return summary
}

// buildOutputText creates the detailed text for the check run output
func (c *Client) buildOutputText(projectScore *scorer.ProjectRiskScore) string {
	if len(projectScore.VulnerabilityScores) == 0 {
		return "No vulnerabilities were found in the scanned dependencies. Your project appears to be secure!"
	}
	
	text := "## Vulnerability Details\n\n"
	
	// Show top vulnerabilities
	maxShow := 20
	if len(projectScore.VulnerabilityScores) < maxShow {
		maxShow = len(projectScore.VulnerabilityScores)
	}
	
	for i := 0; i < maxShow; i++ {
		score := projectScore.VulnerabilityScores[i]
		vuln := score.Vulnerability
		
		riskLevel := "Low"
		emoji := "✅"
		if score.Overall >= 7.0 {
			riskLevel = "High"
			emoji = "🚨"
		} else if score.Overall >= 4.0 {
			riskLevel = "Medium"
			emoji = "⚠️"
		}
		
		text += fmt.Sprintf("### %s %s (%s Risk - %.1f/10)\n", emoji, vuln.ID, riskLevel, score.Overall)
		text += fmt.Sprintf("**Package**: `%s` version `%s`\n", vuln.Package, vuln.Version)
		text += fmt.Sprintf("**CVSS Score**: %.1f (%s)\n", vuln.CVSS, vuln.Severity)
		
		if vuln.Summary != "" {
			text += fmt.Sprintf("**Summary**: %s\n", vuln.Summary)
		}
		
		text += fmt.Sprintf("**Dependency Type**: %s\n", 
			map[bool]string{true: "Direct", false: "Transitive"}[vuln.IsDirect])
		
		// Score breakdown
		text += "**Score Breakdown**:\n"
		text += fmt.Sprintf("- CVSS Component: %.1f\n", score.CVSSComponent)
		text += fmt.Sprintf("- Popularity Component: %.1f\n", score.PopularityComponent)
		text += fmt.Sprintf("- Dependency Component: %.1f\n", score.DependencyComponent)
		text += fmt.Sprintf("- Context Component: %.1f\n", score.ContextComponent)
		
		if len(vuln.References) > 0 {
			text += "**References**:\n"
			for _, ref := range vuln.References {
				text += fmt.Sprintf("- %s\n", ref)
			}
		}
		
		text += "\n---\n\n"
	}
	
	if len(projectScore.VulnerabilityScores) > maxShow {
		text += fmt.Sprintf("*... and %d more vulnerabilities. See the full report for details.*\n", 
			len(projectScore.VulnerabilityScores)-maxShow)
	}
	
	// Add scoring methodology
	text += "## Risk Scoring Methodology\n\n"
	text += "The risk score is calculated using a weighted combination of factors:\n\n"
	text += "- **CVSS Score (50%)**: Base vulnerability severity from the Common Vulnerability Scoring System\n"
	text += "- **Package Popularity (20%)**: Less popular packages may have fewer eyes on security issues\n"
	text += "- **Dependency Type (15%)**: Direct dependencies are easier to update than transitive ones\n"
	text += "- **Context (15%)**: Package type and usage context (e.g., crypto, network, auth libraries are higher risk)\n\n"
	text += "Scores range from 0.0 (lowest risk) to 10.0 (highest risk).\n"
	
	return text
}

// buildCheckRunActions creates actions for failed check runs
func (c *Client) buildCheckRunActions() []*github.CheckRunAction {
	return []*github.CheckRunAction{
		{
			Label:       "View Detailed Report",
			Description: "Open the detailed vulnerability report",
			Identifier:  "view_report",
		},
		{
			Label:       "Update Dependencies", 
			Description: "Get suggestions for updating vulnerable dependencies",
			Identifier:  "update_deps",
		},
	}
}

// UpdateCheckRun updates an existing check run (for long-running scans)
func (c *Client) UpdateCheckRun(ctx context.Context, checkRunID int64, projectScore *scorer.ProjectRiskScore, failThreshold float64) error {
	status := string(CheckRunStatusCompleted)
	conclusion := c.determineConclusion(projectScore.OverallScore, failThreshold)
	conclusionStr := string(conclusion)
	
	now := github.Timestamp{Time: time.Now()}
	output := c.buildCheckRunOutput(projectScore, failThreshold, conclusion)
	
	updateOptions := github.UpdateCheckRunOptions{
		Name:        "Dep-Risk Security Scan",
		Status:      &status,
		Conclusion:  &conclusionStr,
		CompletedAt: &now,
		Output:      &output,
	}
	
	_, _, err := c.client.Checks.UpdateCheckRun(ctx, c.owner, c.repo, checkRunID, updateOptions)
	if err != nil {
		return fmt.Errorf("failed to update check run: %w", err)
	}
	
	return nil
}

// CreateInProgressCheckRun creates a check run in "in_progress" status for long-running scans
func (c *Client) CreateInProgressCheckRun(ctx context.Context) (*github.CheckRun, error) {
	status := string(CheckRunStatusInProgress)
	now := github.Timestamp{Time: time.Now()}
	
	checkRun := github.CreateCheckRunOptions{
		Name:      "Dep-Risk Security Scan",
		HeadSHA:   c.sha,
		Status:    &status,
		StartedAt: &now,
		Output: &github.CheckRunOutput{
			Title:   github.String("🔍 Scanning dependencies for vulnerabilities..."),
			Summary: github.String("Dep-Risk is analyzing your project dependencies for security vulnerabilities."),
		},
	}
	
	result, _, err := c.client.Checks.CreateCheckRun(ctx, c.owner, c.repo, checkRun)
	if err != nil {
		return nil, fmt.Errorf("failed to create in-progress check run: %w", err)
	}
	
	return result, nil
}