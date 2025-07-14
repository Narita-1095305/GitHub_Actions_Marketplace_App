package github

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dep-risk/dep-risk/internal/scorer"
	"github.com/dep-risk/dep-risk/internal/scanner"
)

// UploadSARIF uploads SARIF results to GitHub Security tab
func (c *Client) UploadSARIF(ctx context.Context, sarifPath string) error {
	// Read SARIF file
	sarifData, err := os.ReadFile(sarifPath)
	if err != nil {
		return fmt.Errorf("failed to read SARIF file: %w", err)
	}

	// Encode SARIF data as base64
	sarifBase64 := base64.StdEncoding.EncodeToString(sarifData)

	// Get commit SHA and ref
	commitSha := c.sha
	ref := fmt.Sprintf("refs/heads/%s", c.getBranch())

	// Create SARIF upload request
	uploadRequest := map[string]interface{}{
		"commit_sha": commitSha,
		"ref":        ref,
		"sarif":      sarifBase64,
		"tool_name":  "dep-risk",
	}

	// Convert to JSON
	requestBody, err := json.Marshal(uploadRequest)
	if err != nil {
		return fmt.Errorf("failed to marshal upload request: %w", err)
	}

	// Create HTTP request
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/code-scanning/sarifs", c.owner, c.repo)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(requestBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", os.Getenv("GITHUB_TOKEN")))
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")

	// Send request
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to upload SARIF: %w", err)
	}
	defer resp.Body.Close()

	// Check response
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		
		// Handle specific error cases
		switch resp.StatusCode {
		case http.StatusForbidden:
			return fmt.Errorf("SARIF upload failed: insufficient permissions. Ensure the GITHUB_TOKEN has 'security-events: write' permission")
		case http.StatusNotFound:
			return fmt.Errorf("SARIF upload failed: repository not found or code scanning not enabled")
		case http.StatusUnprocessableEntity:
			return fmt.Errorf("SARIF upload failed: invalid SARIF format or content: %s", string(body))
		default:
			return fmt.Errorf("SARIF upload failed with status %d: %s", resp.StatusCode, string(body))
		}
	}

	// Parse response to get upload ID
	var uploadResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&uploadResponse); err == nil {
		if id, ok := uploadResponse["id"]; ok {
			fmt.Printf("✅ SARIF uploaded successfully to GitHub Security tab (Upload ID: %v)\n", id)
		} else {
			fmt.Printf("✅ SARIF uploaded successfully to GitHub Security tab\n")
		}
	} else {
		fmt.Printf("✅ SARIF uploaded successfully to GitHub Security tab\n")
	}
	
	return nil
}

// getBranch returns the current branch name
func (c *Client) getBranch() string {
	// Try to get branch from environment
	if ref := os.Getenv("GITHUB_REF"); ref != "" {
		if strings.HasPrefix(ref, "refs/heads/") {
			return strings.TrimPrefix(ref, "refs/heads/")
		}
	}
	
	// Default to main if not found
	return "main"
}

// GenerateEnhancedSARIF creates a SARIF report with GitHub-specific enhancements
func (c *Client) GenerateEnhancedSARIF(projectScore *scorer.ProjectRiskScore, outputPath string) error {
	sarif := c.buildSARIFReport(projectScore)
	
	// Write to file
	data, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal SARIF: %w", err)
	}
	
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	
	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write SARIF file: %w", err)
	}
	
	return nil
}

// buildSARIFReport constructs a complete SARIF 2.1.0 report
func (c *Client) buildSARIFReport(projectScore *scorer.ProjectRiskScore) map[string]interface{} {
	return map[string]interface{}{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":            "Dep-Risk",
						"version":         "1.0.0",
						"informationUri":  "https://github.com/dep-risk/dep-risk",
						"shortDescription": map[string]interface{}{
							"text": "Dependency vulnerability scanner with risk scoring",
						},
						"fullDescription": map[string]interface{}{
							"text": "Dep-Risk scans project dependencies for known vulnerabilities and calculates risk scores based on CVSS, popularity, dependency type, and context.",
						},
						"rules": c.buildSARIFRules(projectScore),
					},
				},
				"results": c.buildSARIFResults(projectScore),
				"columnKind": "utf16CodeUnits",
			},
		},
	}
}

// buildSARIFRules creates rule definitions for each vulnerability type
func (c *Client) buildSARIFRules(projectScore *scorer.ProjectRiskScore) []map[string]interface{} {
	rules := make(map[string]map[string]interface{})
	
	for _, score := range projectScore.VulnerabilityScores {
		vuln := score.Vulnerability
		
		if _, exists := rules[vuln.ID]; !exists {
			level := "note"
			if score.Overall >= 7.0 {
				level = "error"
			} else if score.Overall >= 4.0 {
				level = "warning"
			}
			
			rules[vuln.ID] = map[string]interface{}{
				"id": vuln.ID,
				"shortDescription": map[string]interface{}{
					"text": fmt.Sprintf("Vulnerability %s in %s", vuln.ID, vuln.Package),
				},
				"fullDescription": map[string]interface{}{
					"text": vuln.Description,
				},
				"defaultConfiguration": map[string]interface{}{
					"level": level,
				},
				"properties": map[string]interface{}{
					"tags": []string{"security", "vulnerability"},
					"precision": "high",
				},
				"helpUri": c.getHelpUri(vuln),
			}
		}
	}
	
	// Convert map to slice
	var ruleSlice []map[string]interface{}
	for _, rule := range rules {
		ruleSlice = append(ruleSlice, rule)
	}
	
	return ruleSlice
}

// buildSARIFResults creates result entries for each vulnerability
func (c *Client) buildSARIFResults(projectScore *scorer.ProjectRiskScore) []map[string]interface{} {
	var results []map[string]interface{}
	
	for _, score := range projectScore.VulnerabilityScores {
		vuln := score.Vulnerability
		
		level := "note"
		if score.Overall >= 7.0 {
			level = "error"
		} else if score.Overall >= 4.0 {
			level = "warning"
		}
		
		result := map[string]interface{}{
			"ruleId": vuln.ID,
			"level":  level,
			"message": map[string]interface{}{
				"text": fmt.Sprintf("Vulnerability %s found in %s version %s (Risk Score: %.1f/10)", 
					vuln.ID, vuln.Package, vuln.Version, score.Overall),
			},
			"locations": []map[string]interface{}{
				{
					"physicalLocation": map[string]interface{}{
						"artifactLocation": map[string]interface{}{
							"uri": c.getDependencyFile(vuln.Package),
						},
						"region": map[string]interface{}{
							"startLine": 1,
							"startColumn": 1,
						},
					},
				},
			},
			"properties": map[string]interface{}{
				"risk_score":           score.Overall,
				"cvss_score":          vuln.CVSS,
				"severity":            vuln.Severity,
				"package":             vuln.Package,
				"version":             vuln.Version,
				"is_direct":           vuln.IsDirect,
				"cvss_component":      score.CVSSComponent,
				"popularity_component": score.PopularityComponent,
				"dependency_component": score.DependencyComponent,
				"context_component":   score.ContextComponent,
			},
		}
		
		results = append(results, result)
	}
	
	return results
}

// getHelpUri returns a help URI for the vulnerability
func (c *Client) getHelpUri(vuln scanner.Vulnerability) string {
	// Try to find a relevant reference URL
	for _, ref := range vuln.References {
		if strings.Contains(ref, "cve.mitre.org") || 
		   strings.Contains(ref, "nvd.nist.gov") ||
		   strings.Contains(ref, "github.com/advisories") {
			return ref
		}
	}
	
	// Default to OSV database
	return fmt.Sprintf("https://osv.dev/vulnerability/%s", vuln.ID)
}

// getDependencyFile returns the likely dependency file for a package
func (c *Client) getDependencyFile(packageName string) string {
	// This is a simplified implementation
	// In practice, you'd want to track which file each dependency came from
	
	// Check if go.mod exists
	if _, err := os.Stat("go.mod"); err == nil {
		return "go.mod"
	}
	
	// Check if package.json exists
	if _, err := os.Stat("package.json"); err == nil {
		return "package.json"
	}
	
	// Check if requirements.txt exists
	if _, err := os.Stat("requirements.txt"); err == nil {
		return "requirements.txt"
	}
	
	// Default
	return "dependencies"
}