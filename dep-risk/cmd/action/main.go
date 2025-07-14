package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/dep-risk/dep-risk/internal/config"
	"github.com/dep-risk/dep-risk/internal/github"
	"github.com/dep-risk/dep-risk/internal/scanner"
	"github.com/dep-risk/dep-risk/internal/scorer"
)

// ActionResult represents the output of the GitHub Action
type ActionResult struct {
	RiskScore          float64 `json:"risk_score"`
	VulnerabilitiesFound int   `json:"vulnerabilities_found"`
	HighRiskCount      int     `json:"high_risk_count"`
	ScanStatus         string  `json:"scan_status"`
	SarifFile          string  `json:"sarif_file,omitempty"`
	ReportURL          string  `json:"report_url,omitempty"`
}

func main() {
	// Load configuration
	cfg, err := loadConfiguration()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize scanner
	workingDir := cfg.GetWorkingDirectory()
	scannerInstance := scanner.NewScanner(workingDir)

	// Initialize scorer with custom weights
	scoringWeights := scorer.ScoringWeights{
		CVSS:       cfg.CVSSWeight,
		Popularity: cfg.PopularityWeight,
		Dependency: cfg.DependencyWeight,
		Context:    cfg.ContextWeight,
	}
	scorerInstance := scorer.NewScorerWithWeights(scoringWeights)

	// Perform vulnerability scan
	fmt.Println("🔍 Starting vulnerability scan...")
	scanResult, err := scannerInstance.ScanProject()
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	fmt.Printf("📊 Found %d vulnerabilities\n", scanResult.TotalCount)

	// Calculate risk scores
	fmt.Println("⚖️  Calculating risk scores...")
	projectScore := scorerInstance.CalculateProjectScore(scanResult)

	// Filter ignored vulnerabilities
	filteredScores := filterIgnoredVulnerabilities(projectScore.VulnerabilityScores, cfg)
	if len(filteredScores) != len(projectScore.VulnerabilityScores) {
		fmt.Printf("🚫 Ignored %d vulnerabilities based on configuration\n", 
			len(projectScore.VulnerabilityScores)-len(filteredScores))
		
		// Recalculate project score with filtered vulnerabilities
		filteredScanResult := &scanner.ScanResult{
			Vulnerabilities: extractVulnerabilities(filteredScores),
			TotalCount:      len(filteredScores),
		}
		projectScore = scorerInstance.CalculateProjectScore(filteredScanResult)
	}

	// Determine scan status
	scanStatus := determineScanStatus(projectScore.OverallScore, cfg)
	
	// Create action result
	result := ActionResult{
		RiskScore:            projectScore.OverallScore,
		VulnerabilitiesFound: projectScore.Summary.TotalVulnerabilities,
		HighRiskCount:        projectScore.Summary.HighRiskCount,
		ScanStatus:           scanStatus,
	}

	// Generate outputs
	if err := generateOutputs(projectScore, cfg, workingDir); err != nil {
		log.Printf("Warning: Failed to generate some outputs: %v", err)
	}

	// GitHub integration (if running in GitHub Actions)
	if err := handleGitHubIntegration(projectScore, cfg); err != nil {
		log.Printf("Warning: GitHub integration failed: %v", err)
	}

	// API integration (send data to backend)
	if err := handleAPIIntegration(projectScore, cfg); err != nil {
		log.Printf("Warning: API integration failed: %v", err)
	}

	// Print summary
	printSummary(projectScore, cfg)

	// Set GitHub Actions outputs
	setGitHubOutputs(result)

	// Exit with appropriate code
	exitCode := getExitCode(scanStatus, projectScore.OverallScore, cfg)
	if exitCode != 0 {
		fmt.Printf("❌ Scan failed: Risk score %.1f exceeds threshold %.1f\n", 
			projectScore.OverallScore, cfg.FailThreshold)
	} else {
		fmt.Printf("✅ Scan passed: Risk score %.1f is below threshold %.1f\n", 
			projectScore.OverallScore, cfg.FailThreshold)
	}

	os.Exit(exitCode)
}

// loadConfiguration loads the application configuration
func loadConfiguration() (*config.Config, error) {
	cfg := config.DefaultConfig()
	configPath := cfg.GetConfigPath()
	
	return config.LoadConfig(configPath)
}

// filterIgnoredVulnerabilities removes vulnerabilities that should be ignored
func filterIgnoredVulnerabilities(scores []scorer.RiskScore, cfg *config.Config) []scorer.RiskScore {
	var filtered []scorer.RiskScore
	for _, score := range scores {
		if !cfg.ShouldIgnore(score.Vulnerability.ID) {
			filtered = append(filtered, score)
		}
	}
	return filtered
}

// extractVulnerabilities extracts vulnerability objects from risk scores
func extractVulnerabilities(scores []scorer.RiskScore) []scanner.Vulnerability {
	var vulns []scanner.Vulnerability
	for _, score := range scores {
		vulns = append(vulns, score.Vulnerability)
	}
	return vulns
}

// determineScanStatus determines the overall scan status
func determineScanStatus(overallScore float64, cfg *config.Config) string {
	if overallScore >= cfg.FailThreshold {
		return "failure"
	} else if overallScore >= cfg.WarnThreshold {
		return "warning"
	}
	return "success"
}

// generateOutputs generates various output files
func generateOutputs(projectScore *scorer.ProjectRiskScore, cfg *config.Config, workingDir string) error {
	// Generate JSON report
	if err := generateJSONReport(projectScore, workingDir); err != nil {
		return fmt.Errorf("failed to generate JSON report: %w", err)
	}

	// Generate SARIF report if enabled
	if cfg.SarifUpload {
		if err := generateSARIFReport(projectScore, workingDir); err != nil {
			return fmt.Errorf("failed to generate SARIF report: %w", err)
		}
	}

	return nil
}

// generateJSONReport generates a detailed JSON report
func generateJSONReport(projectScore *scorer.ProjectRiskScore, workingDir string) error {
	reportPath := filepath.Join(workingDir, "dep-risk-report.json")
	
	data, err := json.MarshalIndent(projectScore, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(reportPath, data, 0644)
}

// generateSARIFReport generates a SARIF report for GitHub Security tab
func generateSARIFReport(projectScore *scorer.ProjectRiskScore, workingDir string) error {
	// Simplified SARIF structure
	sarif := map[string]interface{}{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":    "dep-risk",
						"version": "1.0.0",
						"informationUri": "https://github.com/dep-risk/dep-risk",
					},
				},
				"results": generateSARIFResults(projectScore),
			},
		},
	}

	sarifPath := filepath.Join(workingDir, "dep-risk.sarif")
	data, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(sarifPath, data, 0644)
}

// generateSARIFResults converts vulnerability scores to SARIF results
func generateSARIFResults(projectScore *scorer.ProjectRiskScore) []map[string]interface{} {
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
				"text": fmt.Sprintf("Vulnerability %s in package %s (version %s): %s", 
					vuln.ID, vuln.Package, vuln.Version, vuln.Summary),
			},
			"properties": map[string]interface{}{
				"risk_score": score.Overall,
				"cvss":       vuln.CVSS,
				"severity":   vuln.Severity,
				"package":    vuln.Package,
				"version":    vuln.Version,
			},
		}

		results = append(results, result)
	}

	return results
}

// printSummary prints a summary of the scan results
func printSummary(projectScore *scorer.ProjectRiskScore, cfg *config.Config) {
	fmt.Println("\n📋 Scan Summary:")
	fmt.Printf("   Overall Risk Score: %.1f/10\n", projectScore.OverallScore)
	fmt.Printf("   Total Vulnerabilities: %d\n", projectScore.Summary.TotalVulnerabilities)
	fmt.Printf("   High Risk: %d\n", projectScore.Summary.HighRiskCount)
	fmt.Printf("   Medium Risk: %d\n", projectScore.Summary.MediumRiskCount)
	fmt.Printf("   Low Risk: %d\n", projectScore.Summary.LowRiskCount)
	fmt.Printf("   Average Score: %.1f\n", projectScore.Summary.AverageScore)
	
	if projectScore.Summary.TotalVulnerabilities > 0 {
		fmt.Println("\n🔍 Top Vulnerabilities:")
		count := 0
		for _, score := range projectScore.VulnerabilityScores {
			if count >= 5 { // Show top 5
				break
			}
			vuln := score.Vulnerability
			fmt.Printf("   • %s in %s v%s (Score: %.1f, CVSS: %.1f)\n",
				vuln.ID, vuln.Package, vuln.Version, score.Overall, vuln.CVSS)
			count++
		}
	}

	fmt.Printf("\n⚙️  Configuration:\n")
	fmt.Printf("   Fail Threshold: %.1f\n", cfg.FailThreshold)
	fmt.Printf("   Warn Threshold: %.1f\n", cfg.WarnThreshold)
	fmt.Printf("   CVSS Weight: %.1f%%\n", cfg.CVSSWeight*100)
	fmt.Printf("   Popularity Weight: %.1f%%\n", cfg.PopularityWeight*100)
	fmt.Printf("   Dependency Weight: %.1f%%\n", cfg.DependencyWeight*100)
	fmt.Printf("   Context Weight: %.1f%%\n", cfg.ContextWeight*100)
}

// setGitHubOutputs sets GitHub Actions output variables
func setGitHubOutputs(result ActionResult) {
	if outputFile := os.Getenv("GITHUB_OUTPUT"); outputFile != "" {
		file, err := os.OpenFile(outputFile, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			log.Printf("Warning: Failed to open GitHub output file: %v", err)
			return
		}
		defer file.Close()

		fmt.Fprintf(file, "risk_score=%.1f\n", result.RiskScore)
		fmt.Fprintf(file, "vulnerabilities_found=%d\n", result.VulnerabilitiesFound)
		fmt.Fprintf(file, "high_risk_count=%d\n", result.HighRiskCount)
		fmt.Fprintf(file, "scan_status=%s\n", result.ScanStatus)
		if result.SarifFile != "" {
			fmt.Fprintf(file, "sarif_file=%s\n", result.SarifFile)
		}
		if result.ReportURL != "" {
			fmt.Fprintf(file, "report_url=%s\n", result.ReportURL)
		}
	}
}

// handleGitHubIntegration handles GitHub-specific integrations
func handleGitHubIntegration(projectScore *scorer.ProjectRiskScore, cfg *config.Config) error {
	// Check if we're running in GitHub Actions
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		return nil // Not in GitHub Actions, skip integration
	}

	ctx := context.Background()
	
	// Initialize GitHub client
	githubClient, err := github.NewClient()
	if err != nil {
		return fmt.Errorf("failed to initialize GitHub client: %w", err)
	}

	// Create Check Run
	fmt.Println("📝 Creating GitHub Check Run...")
	if err := githubClient.CreateCheckRun(ctx, projectScore, cfg.FailThreshold); err != nil {
		log.Printf("Failed to create check run: %v", err)
	} else {
		fmt.Println("✅ Check Run created successfully")
	}

	// Create PR Comment (based on comment mode)
	if shouldCreateComment(projectScore, cfg) {
		fmt.Println("💬 Creating PR comment...")
		if err := githubClient.CreatePRComment(ctx, projectScore); err != nil {
			log.Printf("Failed to create PR comment: %v", err)
		} else {
			fmt.Println("✅ PR comment created successfully")
		}
	}

	// Upload SARIF (if enabled)
	if cfg.SarifUpload {
		sarifPath := filepath.Join(cfg.GetWorkingDirectory(), "dep-risk.sarif")
		if _, err := os.Stat(sarifPath); err == nil {
			fmt.Println("📤 Uploading SARIF to GitHub Security tab...")
			if err := githubClient.UploadSARIF(ctx, sarifPath); err != nil {
				log.Printf("Failed to upload SARIF: %v", err)
			} else {
				fmt.Println("✅ SARIF uploaded successfully")
			}
		}
	}

	return nil
}

// shouldCreateComment determines if a PR comment should be created
func shouldCreateComment(projectScore *scorer.ProjectRiskScore, cfg *config.Config) bool {
	switch cfg.CommentMode {
	case "always":
		return true
	case "never":
		return false
	case "on-failure":
		return projectScore.OverallScore >= cfg.FailThreshold
	default:
		return projectScore.OverallScore >= cfg.FailThreshold
	}
}

// getExitCode determines the appropriate exit code
func getExitCode(scanStatus string, overallScore float64, cfg *config.Config) int {
	switch scanStatus {
	case "failure":
		return 1
	case "warning":
		// For warnings, we don't fail the CI by default
		return 0
	default:
		return 0
	}
}

// ScanData represents the data to send to the API
type ScanData struct {
	Organization     string                 `json:"organization"`
	Repository       string                 `json:"repository"`
	Branch          string                 `json:"branch"`
	CommitSHA       string                 `json:"commit_sha"`
	OverallRiskScore float64               `json:"overall_risk_score"`
	TotalVulns      int                   `json:"total_vulnerabilities"`
	HighRiskCount   int                   `json:"high_risk_count"`
	MediumRiskCount int                   `json:"medium_risk_count"`
	LowRiskCount    int                   `json:"low_risk_count"`
	AverageScore    float64               `json:"average_score"`
	Vulnerabilities []VulnerabilityData   `json:"vulnerabilities"`
	ScanTime        time.Time             `json:"scan_time"`
}

type VulnerabilityData struct {
	CVEID       string  `json:"cve_id"`
	Package     string  `json:"package_name"`
	Version     string  `json:"package_version"`
	RiskScore   float64 `json:"risk_score"`
	CVSSScore   float64 `json:"cvss_score"`
	Severity    string  `json:"severity"`
	IsDirect    bool    `json:"is_direct"`
	Summary     string  `json:"summary"`
}

// handleAPIIntegration sends scan results to the backend API
func handleAPIIntegration(projectScore *scorer.ProjectRiskScore, cfg *config.Config) error {
	apiEndpoint := os.Getenv("DEP_RISK_API_ENDPOINT")
	if apiEndpoint == "" {
		// Skip API integration if no endpoint is configured
		return nil
	}

	// Extract GitHub context
	org := os.Getenv("GITHUB_REPOSITORY_OWNER")
	repo := os.Getenv("GITHUB_REPOSITORY")
	if repo != "" && org != "" {
		// Remove org prefix from repo name
		if len(repo) > len(org)+1 {
			repo = repo[len(org)+1:]
		}
	}
	branch := os.Getenv("GITHUB_REF_NAME")
	commitSHA := os.Getenv("GITHUB_SHA")

	// Convert vulnerability scores to API format
	var vulns []VulnerabilityData
	for _, score := range projectScore.VulnerabilityScores {
		vuln := score.Vulnerability
		vulns = append(vulns, VulnerabilityData{
			CVEID:     vuln.ID,
			Package:   vuln.Package,
			Version:   vuln.Version,
			RiskScore: score.Overall,
			CVSSScore: vuln.CVSS,
			Severity:  vuln.Severity,
			IsDirect:  vuln.IsDirect,
			Summary:   vuln.Summary,
		})
	}

	// Create scan data in the format expected by the API
	apiRequest := map[string]interface{}{
		"organization": org,
		"repository":   repo,
		"branch":       branch,
		"commit_sha":   commitSHA,
		"scan_result": ScanData{
			Organization:     org,
			Repository:       repo,
			Branch:          branch,
			CommitSHA:       commitSHA,
			OverallRiskScore: projectScore.OverallScore,
			TotalVulns:      projectScore.Summary.TotalVulnerabilities,
			HighRiskCount:   projectScore.Summary.HighRiskCount,
			MediumRiskCount: projectScore.Summary.MediumRiskCount,
			LowRiskCount:    projectScore.Summary.LowRiskCount,
			AverageScore:    projectScore.Summary.AverageScore,
			Vulnerabilities: vulns,
			ScanTime:        time.Now(),
		},
		"vulnerabilities": vulns,
	}

	// Send data to API
	fmt.Println("📤 Sending scan results to API...")
	if err := sendToAPI(apiEndpoint, apiRequest); err != nil {
		return fmt.Errorf("failed to send data to API: %w", err)
	}

	fmt.Println("✅ Scan results sent to API successfully")
	return nil
}

// sendToAPI sends scan data to the backend API
func sendToAPI(endpoint string, data interface{}) error {
	url := fmt.Sprintf("%s/api/v1/scans", endpoint)
	
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal scan data: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	
	// Add authentication if available
	if token := os.Getenv("DEP_RISK_API_TOKEN"); token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	return nil
}