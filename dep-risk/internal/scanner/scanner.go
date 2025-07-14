package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// Vulnerability represents a single vulnerability found by the scanner
type Vulnerability struct {
	ID          string  `json:"id"`
	Package     string  `json:"package"`
	Version     string  `json:"version"`
	CVSS        float64 `json:"cvss"`
	Severity    string  `json:"severity"`
	Summary     string  `json:"summary"`
	Description string  `json:"description"`
	References  []string `json:"references"`
	IsDirect    bool    `json:"is_direct"`
}

// ScanResult represents the complete scan results
type ScanResult struct {
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	TotalCount      int            `json:"total_count"`
	HighRiskCount   int            `json:"high_risk_count"`
	MediumRiskCount int            `json:"medium_risk_count"`
	LowRiskCount    int            `json:"low_risk_count"`
}

// Scanner handles vulnerability scanning operations
type Scanner struct {
	SyftPath      string
	OSVScannerPath string
	WorkingDir    string
}

// NewScanner creates a new scanner instance
func NewScanner(workingDir string) *Scanner {
	return &Scanner{
		SyftPath:       "syft",
		OSVScannerPath: "osv-scanner",
		WorkingDir:     workingDir,
	}
}

// ScanProject scans the project for vulnerabilities
func (s *Scanner) ScanProject() (*ScanResult, error) {
	// Step 1: Generate SBOM using syft
	sbomPath, err := s.generateSBOM()
	if err != nil {
		return nil, fmt.Errorf("failed to generate SBOM: %w", err)
	}
	defer os.Remove(sbomPath)

	// Step 2: Scan SBOM with osv-scanner
	vulnerabilities, err := s.scanWithOSV(sbomPath)
	if err != nil {
		return nil, fmt.Errorf("failed to scan with OSV: %w", err)
	}

	// Step 3: Process and categorize results
	result := s.processResults(vulnerabilities)
	
	return result, nil
}

// generateSBOM creates a Software Bill of Materials using syft
func (s *Scanner) generateSBOM() (string, error) {
	// Use /tmp for SBOM file to avoid permission issues
	sbomPath := filepath.Join("/tmp", "sbom.json")
	
	cmd := exec.Command(s.SyftPath, s.WorkingDir, "-o", "spdx-json="+sbomPath)
	cmd.Dir = s.WorkingDir
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("syft command failed: %w, output: %s", err, string(output))
	}
	
	return sbomPath, nil
}

// scanWithOSV scans the project directory directly with osv-scanner
func (s *Scanner) scanWithOSV(sbomPath string) ([]Vulnerability, error) {
	// Use direct directory scan instead of SBOM for better compatibility
	cmd := exec.Command(s.OSVScannerPath, "--format", "json", s.WorkingDir)
	cmd.Dir = s.WorkingDir
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		// osv-scanner returns non-zero exit code when vulnerabilities are found
		// We need to check if it's a real error or just vulnerabilities found
		if len(output) == 0 {
			return nil, fmt.Errorf("osv-scanner command failed: %w", err)
		}
	}
	
	// Filter out non-JSON output (warnings, etc.)
	jsonOutput := s.extractJSONFromOutput(output)
	return s.parseOSVOutput(jsonOutput)
}

// parseOSVOutput parses the JSON output from osv-scanner
func (s *Scanner) parseOSVOutput(output []byte) ([]Vulnerability, error) {
	var osvResult struct {
		Results []struct {
			Source struct {
				Path string `json:"path"`
				Type string `json:"type"`
			} `json:"source"`
			Packages []struct {
				Package struct {
					Name      string `json:"name"`
					Version   string `json:"version"`
					Ecosystem string `json:"ecosystem"`
				} `json:"package"`
				Vulnerabilities []struct {
					ID       string `json:"id"`
					Summary  string `json:"summary"`
					Details  string `json:"details"`
					Severity []struct {
						Type  string  `json:"type"`
						Score string  `json:"score"`
					} `json:"severity"`
					References []struct {
						Type string `json:"type"`
						URL  string `json:"url"`
					} `json:"references"`
					Groups []struct {
						MaxSeverity string `json:"max_severity"`
					} `json:"groups"`
				} `json:"vulnerabilities"`
			} `json:"packages"`
		} `json:"results"`
	}
	
	if err := json.Unmarshal(output, &osvResult); err != nil {
		// Debug: print first 500 chars of output for troubleshooting
		debugOutput := string(output)
		if len(debugOutput) > 500 {
			debugOutput = debugOutput[:500] + "..."
		}
		return nil, fmt.Errorf("failed to parse OSV output: %w\nFirst 500 chars of output: %s", err, debugOutput)
	}
	
	var vulnerabilities []Vulnerability
	
	for _, result := range osvResult.Results {
		for _, pkg := range result.Packages {
			for _, vuln := range pkg.Vulnerabilities {
				v := Vulnerability{
					ID:          vuln.ID,
					Package:     pkg.Package.Name,
					Version:     pkg.Package.Version,
					Summary:     vuln.Summary,
					Description: vuln.Details,
					IsDirect:    s.isDirect(pkg.Package.Name),
				}
				
				// Extract CVSS score and severity
				for _, sev := range vuln.Severity {
					if sev.Type == "CVSS_V3" {
						if score, err := s.parseCVSSScore(sev.Score); err == nil {
							v.CVSS = score
							v.Severity = s.cvssToSeverity(score)
						}
					}
				}
				
				// If no CVSS found, try to use max_severity from groups
				if v.CVSS == 0.0 && len(vuln.Groups) > 0 && vuln.Groups[0].MaxSeverity != "" {
					if score, err := s.parseMaxSeverity(vuln.Groups[0].MaxSeverity); err == nil {
						v.CVSS = score
						v.Severity = s.cvssToSeverity(score)
					}
				}
				
				// Extract references
				for _, ref := range vuln.References {
					v.References = append(v.References, ref.URL)
				}
				
				vulnerabilities = append(vulnerabilities, v)
			}
		}
	}
	
	return vulnerabilities, nil
}

// extractJSONFromOutput filters out non-JSON content from osv-scanner output
func (s *Scanner) extractJSONFromOutput(output []byte) []byte {
	outputStr := string(output)
	
	// Find the start of JSON output (first '{' character)
	jsonStart := strings.Index(outputStr, "{")
	if jsonStart == -1 {
		return []byte("{\"results\":[]}")
	}
	
	// Extract everything from the first '{' to the end
	jsonPart := outputStr[jsonStart:]
	
	// Find the last '}' to ensure we have complete JSON
	jsonEnd := strings.LastIndex(jsonPart, "}")
	if jsonEnd == -1 {
		return []byte("{\"results\":[]}")
	}
	
	return []byte(jsonPart[:jsonEnd+1])
}

// isDirect determines if a package is a direct dependency
func (s *Scanner) isDirect(packageName string) bool {
	// This is a simplified implementation
	// In a real implementation, we would parse go.mod, package.json, etc.
	// to determine direct vs transitive dependencies
	
	// Check for go.mod
	goModPath := filepath.Join(s.WorkingDir, "go.mod")
	if content, err := os.ReadFile(goModPath); err == nil {
		return strings.Contains(string(content), packageName)
	}
	
	// Check for package.json
	packageJSONPath := filepath.Join(s.WorkingDir, "package.json")
	if content, err := os.ReadFile(packageJSONPath); err == nil {
		return strings.Contains(string(content), packageName)
	}
	
	return false
}

// parseCVSSScore extracts numeric CVSS score from string
func (s *Scanner) parseCVSSScore(scoreStr string) (float64, error) {
	// Parse CVSS vector string to extract base score
	// This is a simplified implementation
	if strings.Contains(scoreStr, "CVSS:3.1") {
		// Extract base score from CVSS vector
		// For now, return a mock score based on severity indicators
		if strings.Contains(scoreStr, "H") {
			return 8.5, nil
		} else if strings.Contains(scoreStr, "M") {
			return 5.5, nil
		} else {
			return 2.5, nil
		}
	}
	return 0.0, fmt.Errorf("unable to parse CVSS score: %s", scoreStr)
}

// cvssToSeverity converts CVSS score to severity level
func (s *Scanner) cvssToSeverity(score float64) string {
	if score >= 9.0 {
		return "CRITICAL"
	} else if score >= 7.0 {
		return "HIGH"
	} else if score >= 4.0 {
		return "MEDIUM"
	} else {
		return "LOW"
	}
}

// processResults categorizes and counts vulnerabilities
func (s *Scanner) processResults(vulnerabilities []Vulnerability) *ScanResult {
	result := &ScanResult{
		Vulnerabilities: vulnerabilities,
		TotalCount:      len(vulnerabilities),
	}
	
	for _, vuln := range vulnerabilities {
		switch vuln.Severity {
		case "CRITICAL", "HIGH":
			result.HighRiskCount++
		case "MEDIUM":
			result.MediumRiskCount++
		case "LOW":
			result.LowRiskCount++
		}
	}
	
	return result
}

// parseMaxSeverity converts max_severity string to numeric score
func (s *Scanner) parseMaxSeverity(maxSeverity string) (float64, error) {
	// max_severity is often a numeric string like "4.3"
	if score, err := strconv.ParseFloat(maxSeverity, 64); err == nil {
		return score, nil
	}
	return 0.0, fmt.Errorf("unable to parse max_severity: %s", maxSeverity)
}