package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config represents the application configuration
type Config struct {
	FailThreshold    float64  `yaml:"fail_threshold"`
	WarnThreshold    float64  `yaml:"warn_threshold"`
	ScanPaths        []string `yaml:"scan_paths"`
	ExcludePaths     []string `yaml:"exclude_paths"`
	Languages        []string `yaml:"languages"`
	IgnoreList       []string `yaml:"ignore_list"`
	CVSSWeight       float64  `yaml:"cvss_weight"`
	PopularityWeight float64  `yaml:"popularity_weight"`
	DependencyWeight float64  `yaml:"dependency_weight"`
	ContextWeight    float64  `yaml:"context_weight"`
	CommentMode      string   `yaml:"comment_mode"`
	SarifUpload      bool     `yaml:"sarif_upload"`
	DashboardUpload  bool     `yaml:"dashboard_upload"`
	Timeout          int      `yaml:"timeout"`
	ParallelJobs     int      `yaml:"parallel_jobs"`
	CacheEnabled     bool     `yaml:"cache_enabled"`
	CacheTTL         int      `yaml:"cache_ttl"`
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		FailThreshold:    7.0,
		WarnThreshold:    3.0,
		ScanPaths:        []string{},
		ExcludePaths:     []string{"node_modules", "vendor", ".git"},
		Languages:        []string{"auto"},
		IgnoreList:       []string{},
		CVSSWeight:       0.5,
		PopularityWeight: 0.2,
		DependencyWeight: 0.15,
		ContextWeight:    0.15,
		CommentMode:      "on-failure",
		SarifUpload:      true,
		DashboardUpload:  true,
		Timeout:          300,
		ParallelJobs:     4,
		CacheEnabled:     true,
		CacheTTL:         24,
	}
}

// LoadConfig loads configuration from file and environment variables
func LoadConfig(configPath string) (*Config, error) {
	config := DefaultConfig()

	// Load from file if it exists
	if configPath != "" && fileExists(configPath) {
		if err := config.loadFromFile(configPath); err != nil {
			return nil, fmt.Errorf("failed to load config file: %w", err)
		}
	}

	// Override with environment variables (GitHub Actions inputs)
	config.loadFromEnv()

	// Validate configuration
	if err := config.validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return config, nil
}

// loadFromFile loads configuration from a YAML file
func (c *Config) loadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	return yaml.Unmarshal(data, c)
}

// loadFromEnv loads configuration from environment variables
func (c *Config) loadFromEnv() {
	if val := os.Getenv("INPUT_FAIL_THRESHOLD"); val != "" {
		if f, err := strconv.ParseFloat(val, 64); err == nil {
			c.FailThreshold = f
		}
	}

	if val := os.Getenv("INPUT_WARN_THRESHOLD"); val != "" {
		if f, err := strconv.ParseFloat(val, 64); err == nil {
			c.WarnThreshold = f
		}
	}

	if val := os.Getenv("INPUT_SCAN_PATHS"); val != "" {
		c.ScanPaths = strings.Split(val, ",")
		for i := range c.ScanPaths {
			c.ScanPaths[i] = strings.TrimSpace(c.ScanPaths[i])
		}
	}

	if val := os.Getenv("INPUT_EXCLUDE_PATHS"); val != "" {
		c.ExcludePaths = strings.Split(val, ",")
		for i := range c.ExcludePaths {
			c.ExcludePaths[i] = strings.TrimSpace(c.ExcludePaths[i])
		}
	}

	if val := os.Getenv("INPUT_LANGUAGES"); val != "" {
		c.Languages = strings.Split(val, ",")
		for i := range c.Languages {
			c.Languages[i] = strings.TrimSpace(c.Languages[i])
		}
	}

	if val := os.Getenv("INPUT_CVSS_WEIGHT"); val != "" {
		if f, err := strconv.ParseFloat(val, 64); err == nil {
			c.CVSSWeight = f
		}
	}

	if val := os.Getenv("INPUT_POPULARITY_WEIGHT"); val != "" {
		if f, err := strconv.ParseFloat(val, 64); err == nil {
			c.PopularityWeight = f
		}
	}

	if val := os.Getenv("INPUT_DEPENDENCY_WEIGHT"); val != "" {
		if f, err := strconv.ParseFloat(val, 64); err == nil {
			c.DependencyWeight = f
		}
	}

	if val := os.Getenv("INPUT_CONTEXT_WEIGHT"); val != "" {
		if f, err := strconv.ParseFloat(val, 64); err == nil {
			c.ContextWeight = f
		}
	}

	if val := os.Getenv("INPUT_COMMENT_MODE"); val != "" {
		c.CommentMode = val
	}

	if val := os.Getenv("INPUT_SARIF_UPLOAD"); val != "" {
		c.SarifUpload = val == "true"
	}

	if val := os.Getenv("INPUT_DASHBOARD_UPLOAD"); val != "" {
		c.DashboardUpload = val == "true"
	}

	if val := os.Getenv("INPUT_TIMEOUT"); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			c.Timeout = i
		}
	}

	if val := os.Getenv("INPUT_PARALLEL_JOBS"); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			c.ParallelJobs = i
		}
	}

	if val := os.Getenv("INPUT_CACHE_ENABLED"); val != "" {
		c.CacheEnabled = val == "true"
	}

	if val := os.Getenv("INPUT_CACHE_TTL"); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			c.CacheTTL = i
		}
	}
}

// validate checks if the configuration is valid
func (c *Config) validate() error {
	if c.FailThreshold < 0 || c.FailThreshold > 10 {
		return fmt.Errorf("fail_threshold must be between 0 and 10")
	}

	if c.WarnThreshold < 0 || c.WarnThreshold > 10 {
		return fmt.Errorf("warn_threshold must be between 0 and 10")
	}

	if c.WarnThreshold > c.FailThreshold {
		return fmt.Errorf("warn_threshold cannot be greater than fail_threshold")
	}

	// Validate weights sum to approximately 1.0
	totalWeight := c.CVSSWeight + c.PopularityWeight + c.DependencyWeight + c.ContextWeight
	if totalWeight < 0.9 || totalWeight > 1.1 {
		return fmt.Errorf("scoring weights must sum to approximately 1.0, got %.2f", totalWeight)
	}

	validCommentModes := []string{"always", "on-failure", "never"}
	if !contains(validCommentModes, c.CommentMode) {
		return fmt.Errorf("comment_mode must be one of: %s", strings.Join(validCommentModes, ", "))
	}

	if c.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}

	if c.ParallelJobs <= 0 {
		return fmt.Errorf("parallel_jobs must be positive")
	}

	return nil
}

// GetScoringWeights returns the scoring weights from the configuration
func (c *Config) GetScoringWeights() (float64, float64, float64, float64) {
	return c.CVSSWeight, c.PopularityWeight, c.DependencyWeight, c.ContextWeight
}

// ShouldIgnore checks if a vulnerability should be ignored
func (c *Config) ShouldIgnore(vulnID string) bool {
	return contains(c.IgnoreList, vulnID)
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// contains checks if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// GetWorkingDirectory returns the working directory for scanning
func (c *Config) GetWorkingDirectory() string {
	if wd := os.Getenv("GITHUB_WORKSPACE"); wd != "" {
		return wd
	}
	if wd, err := os.Getwd(); err == nil {
		return wd
	}
	return "."
}

// GetConfigPath returns the path to the configuration file
func (c *Config) GetConfigPath() string {
	if configPath := os.Getenv("INPUT_SCORING_CONFIG"); configPath != "" {
		return filepath.Join(c.GetWorkingDirectory(), configPath)
	}
	return filepath.Join(c.GetWorkingDirectory(), ".github", "dep-risk.yml")
}