package database

import (
	"fmt"
	"log"
	"os"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/dep-risk/dep-risk/internal/models"
)

// DB is the global database instance
var DB *gorm.DB

// Config represents database configuration
type Config struct {
	Host     string
	Port     string
	User     string
	Password string
	DBName   string
	SSLMode  string
}

// LoadConfigFromEnv loads database configuration from environment variables
func LoadConfigFromEnv() *Config {
	return &Config{
		Host:     getEnvOrDefault("DB_HOST", "localhost"),
		Port:     getEnvOrDefault("DB_PORT", "5432"),
		User:     getEnvOrDefault("DB_USER", "user"),
		Password: getEnvOrDefault("DB_PASSWORD", "password"),
		DBName:   getEnvOrDefault("DB_NAME", "deprisk"),
		SSLMode:  getEnvOrDefault("DB_SSLMODE", "disable"),
	}
}

// getEnvOrDefault returns environment variable value or default
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// Connect establishes a connection to the database
func Connect(config *Config) error {
	dsn := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		config.Host, config.Port, config.User, config.Password, config.DBName, config.SSLMode,
	)

	// Configure GORM logger
	gormLogger := logger.Default
	if os.Getenv("ENV") == "production" {
		gormLogger = logger.Default.LogMode(logger.Silent)
	} else {
		gormLogger = logger.Default.LogMode(logger.Info)
	}

	// Open database connection
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: gormLogger,
		NowFunc: func() time.Time {
			return time.Now().UTC()
		},
	})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	// Configure connection pool
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("failed to get database instance: %w", err)
	}

	// Set connection pool settings
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)

	DB = db
	log.Println("✅ Database connected successfully")
	return nil
}

// Migrate runs database migrations
func Migrate() error {
	if DB == nil {
		return fmt.Errorf("database not connected")
	}

	// Auto-migrate all models
	err := DB.AutoMigrate(
		&models.Organization{},
		&models.Repository{},
		&models.Scan{},
		&models.Vulnerability{},
	)
	if err != nil {
		return fmt.Errorf("failed to migrate database: %w", err)
	}

	log.Println("✅ Database migration completed")
	return nil
}

// Close closes the database connection
func Close() error {
	if DB == nil {
		return nil
	}

	sqlDB, err := DB.DB()
	if err != nil {
		return err
	}

	return sqlDB.Close()
}

// GetDB returns the database instance
func GetDB() *gorm.DB {
	return DB
}

// HealthCheck performs a database health check
func HealthCheck() error {
	if DB == nil {
		return fmt.Errorf("database not connected")
	}

	sqlDB, err := DB.DB()
	if err != nil {
		return err
	}

	return sqlDB.Ping()
}

// Transaction executes a function within a database transaction
func Transaction(fn func(*gorm.DB) error) error {
	return DB.Transaction(fn)
}

// CreateIndexes creates additional database indexes for performance
func CreateIndexes() error {
	if DB == nil {
		return fmt.Errorf("database not connected")
	}

	// Create indexes for better query performance
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_scans_repo_id_created_at ON scans(repo_id, created_at DESC)",
		"CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan_id ON vulnerabilities(scan_id)",
		"CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve_id ON vulnerabilities(cve_id)",
		"CREATE INDEX IF NOT EXISTS idx_repositories_org_id ON repositories(org_id)",
		"CREATE INDEX IF NOT EXISTS idx_scans_commit_sha ON scans(commit_sha)",
		"CREATE INDEX IF NOT EXISTS idx_scans_overall_risk_score ON scans(overall_risk_score DESC)",
	}

	for _, indexSQL := range indexes {
		if err := DB.Exec(indexSQL).Error; err != nil {
			log.Printf("Warning: Failed to create index: %v", err)
		}
	}

	log.Println("✅ Database indexes created")
	return nil
}

// SeedData inserts initial data for development/testing
func SeedData() error {
	if DB == nil {
		return fmt.Errorf("database not connected")
	}

	// Check if data already exists
	var count int64
	DB.Model(&models.Organization{}).Count(&count)
	if count > 0 {
		log.Println("ℹ️  Database already contains data, skipping seed")
		return nil
	}

	// Create sample organization
	org := &models.Organization{
		GitHubOrg: "example-org",
		Name:      "Example Organization",
	}

	if err := DB.Create(org).Error; err != nil {
		return fmt.Errorf("failed to create sample organization: %w", err)
	}

	// Create sample repository
	repo := &models.Repository{
		OrgID:      org.ID,
		GitHubRepo: "example-org/sample-repo",
		Name:       "Sample Repository",
		Language:   "Go",
	}

	if err := DB.Create(repo).Error; err != nil {
		return fmt.Errorf("failed to create sample repository: %w", err)
	}

	log.Println("✅ Sample data seeded")
	return nil
}