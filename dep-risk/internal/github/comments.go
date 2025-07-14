package github

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/go-github/v57/github"
	"github.com/dep-risk/dep-risk/internal/scorer"
)

// CommentTemplate defines the structure for PR comments
type CommentTemplate struct {
	Header      string
	Summary     string
	Details     string
	Footer      string
	RiskLevel   string
	Emoji       string
}

// CreatePRComment creates or updates a PR comment with scan results
func (c *Client) CreatePRComment(ctx context.Context, projectScore *scorer.ProjectRiskScore) error {
	if c.pr == 0 {
		return fmt.Errorf("no PR number available for commenting")
	}

	comment := c.generateCommentBody(projectScore)
	
	// Check if we already have a comment from this bot
	existingComment, err := c.findExistingComment(ctx)
	if err != nil {
		return fmt.Errorf("failed to find existing comment: %w", err)
	}

	if existingComment != nil {
		// Update existing comment
		existingComment.Body = &comment
		_, _, err = c.client.Issues.EditComment(ctx, c.owner, c.repo, *existingComment.ID, existingComment)
		if err != nil {
			return fmt.Errorf("failed to update PR comment: %w", err)
		}
	} else {
		// Create new comment
		issueComment := &github.IssueComment{
			Body: &comment,
		}
		_, _, err = c.client.Issues.CreateComment(ctx, c.owner, c.repo, c.pr, issueComment)
		if err != nil {
			return fmt.Errorf("failed to create PR comment: %w", err)
		}
	}

	return nil
}

// findExistingComment looks for an existing dep-risk comment
func (c *Client) findExistingComment(ctx context.Context) (*github.IssueComment, error) {
	comments, _, err := c.client.Issues.ListComments(ctx, c.owner, c.repo, c.pr, nil)
	if err != nil {
		return nil, err
	}

	for _, comment := range comments {
		if comment.Body != nil && strings.Contains(*comment.Body, "<!-- dep-risk-comment -->") {
			return comment, nil
		}
	}

	return nil, nil
}

// generateCommentBody creates the markdown comment body
func (c *Client) generateCommentBody(projectScore *scorer.ProjectRiskScore) string {
	template := c.getCommentTemplate(projectScore)
	
	var builder strings.Builder
	
	// Hidden marker for identifying our comments
	builder.WriteString("<!-- dep-risk-comment -->\n")
	
	// Header with emoji and risk level
	builder.WriteString(fmt.Sprintf("## %s Dep-Risk Security Scan Results\n\n", template.Emoji))
	
	// Summary section
	builder.WriteString("### 📊 Summary\n")
	builder.WriteString(fmt.Sprintf("- **Overall Risk Score**: %.1f/10 (%s)\n", 
		projectScore.OverallScore, template.RiskLevel))
	builder.WriteString(fmt.Sprintf("- **Total Vulnerabilities**: %d\n", 
		projectScore.Summary.TotalVulnerabilities))
	builder.WriteString(fmt.Sprintf("- **High Risk**: %d | **Medium Risk**: %d | **Low Risk**: %d\n", 
		projectScore.Summary.HighRiskCount, 
		projectScore.Summary.MediumRiskCount, 
		projectScore.Summary.LowRiskCount))
	
	if projectScore.Summary.TotalVulnerabilities > 0 {
		builder.WriteString(fmt.Sprintf("- **Average Score**: %.1f/10\n", 
			projectScore.Summary.AverageScore))
	}
	
	builder.WriteString("\n")
	
	// Detailed vulnerabilities section
	if len(projectScore.VulnerabilityScores) > 0 {
		builder.WriteString("### 🔍 Vulnerability Details\n\n")
		
		// Show top 10 vulnerabilities
		maxShow := 10
		if len(projectScore.VulnerabilityScores) < maxShow {
			maxShow = len(projectScore.VulnerabilityScores)
		}
		
		builder.WriteString("| Vulnerability | Package | Version | Risk Score | CVSS | Severity |\n")
		builder.WriteString("|---------------|---------|---------|------------|------|----------|\n")
		
		for i := 0; i < maxShow; i++ {
			score := projectScore.VulnerabilityScores[i]
			vuln := score.Vulnerability
			
			riskEmoji := c.getRiskEmoji(score.Overall)
			builder.WriteString(fmt.Sprintf("| %s %s | `%s` | `%s` | %.1f %s | %.1f | %s |\n",
				riskEmoji, vuln.ID, vuln.Package, vuln.Version, 
				score.Overall, c.getRiskLevel(score.Overall), vuln.CVSS, vuln.Severity))
		}
		
		if len(projectScore.VulnerabilityScores) > maxShow {
			builder.WriteString(fmt.Sprintf("\n*... and %d more vulnerabilities*\n", 
				len(projectScore.VulnerabilityScores)-maxShow))
		}
		
		builder.WriteString("\n")
	}
	
	// Risk breakdown section
	if projectScore.Summary.TotalVulnerabilities > 0 {
		builder.WriteString("### ⚖️ Risk Score Breakdown\n")
		builder.WriteString("The risk score is calculated using multiple factors:\n\n")
		builder.WriteString("- **CVSS Score** (50%): Base vulnerability severity\n")
		builder.WriteString("- **Package Popularity** (20%): Less popular packages are riskier\n")
		builder.WriteString("- **Dependency Type** (15%): Direct dependencies are easier to update\n")
		builder.WriteString("- **Context** (15%): Package type and usage context\n\n")
	}
	
	// Footer with timestamp and actions
	builder.WriteString("---\n")
	builder.WriteString(fmt.Sprintf("*Scanned at %s by [Dep-Risk](https://github.com/dep-risk/dep-risk)*\n", 
		time.Now().UTC().Format("2006-01-02 15:04:05 UTC")))
	
	if projectScore.OverallScore >= 7.0 {
		builder.WriteString("\n💡 **Recommended Actions**:\n")
		builder.WriteString("- Review and update vulnerable packages\n")
		builder.WriteString("- Consider alternative packages for high-risk dependencies\n")
		builder.WriteString("- Add vulnerable packages to ignore list if risk is acceptable\n")
	}
	
	return builder.String()
}

// getCommentTemplate returns the appropriate template based on risk score
func (c *Client) getCommentTemplate(projectScore *scorer.ProjectRiskScore) CommentTemplate {
	score := projectScore.OverallScore
	
	if score >= 7.0 {
		return CommentTemplate{
			RiskLevel: "High Risk",
			Emoji:     "🚨",
		}
	} else if score >= 4.0 {
		return CommentTemplate{
			RiskLevel: "Medium Risk", 
			Emoji:     "⚠️",
		}
	} else {
		return CommentTemplate{
			RiskLevel: "Low Risk",
			Emoji:     "✅",
		}
	}
}

// getRiskEmoji returns emoji based on risk score
func (c *Client) getRiskEmoji(score float64) string {
	if score >= 7.0 {
		return "🚨"
	} else if score >= 4.0 {
		return "⚠️"
	} else {
		return "✅"
	}
}

// getRiskLevel returns risk level text based on score
func (c *Client) getRiskLevel(score float64) string {
	if score >= 7.0 {
		return "High"
	} else if score >= 4.0 {
		return "Medium"
	} else {
		return "Low"
	}
}