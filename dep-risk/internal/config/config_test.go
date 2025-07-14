package config

import (
	"os"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	
	if cfg.FailThreshold != 7.0 {
		t.Errorf("Expected FailThreshold 7.0, got %f", cfg.FailThreshold)
	}
	
	if cfg.WarnThreshold != 3.0 {
		t.Errorf("Expected WarnThreshold 3.0, got %f", cfg.WarnThreshold)
	}
	
	if cfg.CVSSWeight != 0.5 {
		t.Errorf("Expected CVSSWeight 0.5, got %f", cfg.CVSSWeight)
	}
}

func TestLoadFromEnv(t *testing.T) {
	// Set environment variables
	os.Setenv("INPUT_FAIL_THRESHOLD", "8.5")
	os.Setenv("INPUT_WARN_THRESHOLD", "4.0")
	os.Setenv("INPUT_CVSS_WEIGHT", "0.6")
	
	defer func() {
		os.Unsetenv("INPUT_FAIL_THRESHOLD")
		os.Unsetenv("INPUT_WARN_THRESHOLD")
		os.Unsetenv("INPUT_CVSS_WEIGHT")
	}()
	
	cfg := DefaultConfig()
	cfg.loadFromEnv()
	
	if cfg.FailThreshold != 8.5 {
		t.Errorf("Expected FailThreshold 8.5, got %f", cfg.FailThreshold)
	}
	
	if cfg.WarnThreshold != 4.0 {
		t.Errorf("Expected WarnThreshold 4.0, got %f", cfg.WarnThreshold)
	}
	
	if cfg.CVSSWeight != 0.6 {
		t.Errorf("Expected CVSSWeight 0.6, got %f", cfg.CVSSWeight)
	}
}

func TestValidation(t *testing.T) {
	cfg := DefaultConfig()
	
	// Valid configuration should pass
	if err := cfg.validate(); err != nil {
		t.Errorf("Valid configuration failed validation: %v", err)
	}
	
	// Invalid fail threshold
	cfg.FailThreshold = 11.0
	if err := cfg.validate(); err == nil {
		t.Error("Expected validation error for fail_threshold > 10")
	}
	
	// Reset and test warn > fail
	cfg = DefaultConfig()
	cfg.WarnThreshold = 8.0
	cfg.FailThreshold = 7.0
	if err := cfg.validate(); err == nil {
		t.Error("Expected validation error for warn_threshold > fail_threshold")
	}
}