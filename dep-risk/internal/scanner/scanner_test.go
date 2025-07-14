package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestNewScanner(t *testing.T) {
	workingDir := "/tmp/test"
	scanner := NewScanner(workingDir)
	
	if scanner.WorkingDir != workingDir {
		t.Errorf("Expected WorkingDir %s, got %s", workingDir, scanner.WorkingDir)
	}
	
	if scanner.SyftPath != "syft" {
		t.Errorf("Expected SyftPath 'syft', got %s", scanner.SyftPath)
	}
	
	if scanner.OSVScannerPath != "osv-scanner" {
		t.Errorf("Expected OSVScannerPath 'osv-scanner', got %s", scanner.OSVScannerPath)
	}
}

func TestParseOSVOutput(t *testing.T) {
	scanner := NewScanner("/tmp")
	
	// Mock OSV output based on real structure
	mockOutput := `{
		"results": [
			{
				"source": {
					"path": "/test/go.mod",
					"type": "lockfile"
				},
				"packages": [
					{
						"package": {
							"name": "github.com/gin-gonic/gin",
							"version": "1.9.0",
							"ecosystem": "Go"
						},
						"vulnerabilities": [
							{
								"id": "GHSA-2c4m-59x9-fr2g",
								"summary": "Test vulnerability",
								"details": "Test details",
								"severity": [
									{
										"type": "CVSS_V3",
										"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"
									}
								],
								"references": [
									{
										"type": "ADVISORY",
										"url": "https://example.com/advisory"
									}
								],
								"groups": [
									{
										"max_severity": "4.3"
									}
								]
							}
						]
					}
				]
			}
		]
	}`
	
	vulnerabilities, err := scanner.parseOSVOutput([]byte(mockOutput))
	if err != nil {
		t.Fatalf("parseOSVOutput failed: %v", err)
	}
	
	if len(vulnerabilities) != 1 {
		t.Fatalf("Expected 1 vulnerability, got %d", len(vulnerabilities))
	}
	
	vuln := vulnerabilities[0]
	if vuln.ID != "GHSA-2c4m-59x9-fr2g" {
		t.Errorf("Expected ID 'GHSA-2c4m-59x9-fr2g', got %s", vuln.ID)
	}
	
	if vuln.Package != "github.com/gin-gonic/gin" {
		t.Errorf("Expected Package 'github.com/gin-gonic/gin', got %s", vuln.Package)
	}
	
	if vuln.Version != "1.9.0" {
		t.Errorf("Expected Version '1.9.0', got %s", vuln.Version)
	}
	
	if vuln.Summary != "Test vulnerability" {
		t.Errorf("Expected Summary 'Test vulnerability', got %s", vuln.Summary)
	}
}

func TestExtractJSONFromOutput(t *testing.T) {
	scanner := NewScanner("/tmp")
	
	// Test with mixed output (warnings + JSON)
	mixedOutput := `Scanning dir .
Scanned /test/go.mod file and found 4 packages
{
  "results": [
    {
      "source": {
        "path": "/test/go.mod",
        "type": "lockfile"
      }
    }
  ]
}`
	
	jsonOutput := scanner.extractJSONFromOutput([]byte(mixedOutput))
	
	// Verify it's valid JSON
	var result map[string]interface{}
	if err := json.Unmarshal(jsonOutput, &result); err != nil {
		t.Fatalf("Extracted output is not valid JSON: %v", err)
	}
	
	// Verify structure
	if results, ok := result["results"].([]interface{}); !ok || len(results) == 0 {
		t.Error("Expected results array in extracted JSON")
	}
}

func TestIsDirect(t *testing.T) {
	// Create temporary test directory
	tempDir, err := os.MkdirTemp("", "scanner_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)
	
	scanner := NewScanner(tempDir)
	
	// Create test go.mod file
	goModContent := `module test-project

go 1.21

require (
	github.com/gin-gonic/gin v1.9.0
	github.com/gorilla/mux v1.8.0
)`
	
	goModPath := filepath.Join(tempDir, "go.mod")
	if err := os.WriteFile(goModPath, []byte(goModContent), 0644); err != nil {
		t.Fatalf("Failed to write go.mod: %v", err)
	}
	
	// Test direct dependency
	if !scanner.isDirect("github.com/gin-gonic/gin") {
		t.Error("Expected gin to be detected as direct dependency")
	}
	
	// Test indirect dependency
	if scanner.isDirect("github.com/some/indirect") {
		t.Error("Expected indirect package to not be detected as direct")
	}
}

func TestParseCVSSScore(t *testing.T) {
	scanner := NewScanner("/tmp")
	
	tests := []struct {
		input    string
		expected float64
		hasError bool
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N", 8.5, false}, // High severity
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:M/A:N", 5.5, false}, // Medium severity
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", 2.5, false}, // Low severity
		{"invalid", 0.0, true},
	}
	
	for _, test := range tests {
		score, err := scanner.parseCVSSScore(test.input)
		
		if test.hasError {
			if err == nil {
				t.Errorf("Expected error for input %s, but got none", test.input)
			}
		} else {
			if err != nil {
				t.Errorf("Unexpected error for input %s: %v", test.input, err)
			}
			if score != test.expected {
				t.Errorf("Expected score %f for input %s, got %f", test.expected, test.input, score)
			}
		}
	}
}

func TestCvssToSeverity(t *testing.T) {
	scanner := NewScanner("/tmp")
	
	tests := []struct {
		score    float64
		expected string
	}{
		{9.5, "CRITICAL"},
		{8.0, "HIGH"},
		{5.0, "MEDIUM"},
		{2.0, "LOW"},
	}
	
	for _, test := range tests {
		severity := scanner.cvssToSeverity(test.score)
		if severity != test.expected {
			t.Errorf("Expected severity %s for score %f, got %s", test.expected, test.score, severity)
		}
	}
}

func TestParseMaxSeverity(t *testing.T) {
	scanner := NewScanner("/tmp")
	
	tests := []struct {
		input    string
		expected float64
		hasError bool
	}{
		{"4.3", 4.3, false},
		{"8.5", 8.5, false},
		{"0.0", 0.0, false},
		{"invalid", 0.0, true},
		{"", 0.0, true},
	}
	
	for _, test := range tests {
		score, err := scanner.parseMaxSeverity(test.input)
		
		if test.hasError {
			if err == nil {
				t.Errorf("Expected error for input %s, but got none", test.input)
			}
		} else {
			if err != nil {
				t.Errorf("Unexpected error for input %s: %v", test.input, err)
			}
			if score != test.expected {
				t.Errorf("Expected score %f for input %s, got %f", test.expected, test.input, score)
			}
		}
	}
}

func TestProcessResults(t *testing.T) {
	scanner := NewScanner("/tmp")
	
	vulnerabilities := []Vulnerability{
		{ID: "1", Severity: "CRITICAL"},
		{ID: "2", Severity: "HIGH"},
		{ID: "3", Severity: "MEDIUM"},
		{ID: "4", Severity: "LOW"},
		{ID: "5", Severity: "HIGH"},
	}
	
	result := scanner.processResults(vulnerabilities)
	
	if result.TotalCount != 5 {
		t.Errorf("Expected TotalCount 5, got %d", result.TotalCount)
	}
	
	if result.HighRiskCount != 3 { // CRITICAL + HIGH
		t.Errorf("Expected HighRiskCount 3, got %d", result.HighRiskCount)
	}
	
	if result.MediumRiskCount != 1 {
		t.Errorf("Expected MediumRiskCount 1, got %d", result.MediumRiskCount)
	}
	
	if result.LowRiskCount != 1 {
		t.Errorf("Expected LowRiskCount 1, got %d", result.LowRiskCount)
	}
}