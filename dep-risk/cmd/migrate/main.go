package main

import (
	"flag"
	"log"
	"os"

	"github.com/dep-risk/dep-risk/internal/database"
)

func main() {
	var (
		seedFlag = flag.Bool("seed", false, "Seed database with sample data")
		dropFlag = flag.Bool("drop", false, "Drop all tables (DANGEROUS)")
	)
	flag.Parse()

	// Load database configuration
	config := database.LoadConfigFromEnv()

	// Connect to database
	if err := database.Connect(config); err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer database.Close()

	// Handle drop flag
	if *dropFlag {
		if os.Getenv("ENV") == "production" {
			log.Fatal("❌ Cannot drop tables in production environment")
		}
		
		log.Println("⚠️  Dropping all tables...")
		db := database.GetDB()
		
		// Drop tables in reverse order to handle foreign keys
		tables := []string{"vulnerabilities", "scans", "repositories", "organizations"}
		for _, table := range tables {
			if err := db.Exec("DROP TABLE IF EXISTS " + table + " CASCADE").Error; err != nil {
				log.Printf("Warning: Failed to drop table %s: %v", table, err)
			}
		}
		log.Println("✅ All tables dropped")
	}

	// Run migrations
	log.Println("🔄 Running database migrations...")
	if err := database.Migrate(); err != nil {
		log.Fatalf("Migration failed: %v", err)
	}

	// Create indexes
	log.Println("🔄 Creating database indexes...")
	if err := database.CreateIndexes(); err != nil {
		log.Fatalf("Index creation failed: %v", err)
	}

	// Seed data if requested
	if *seedFlag {
		log.Println("🌱 Seeding database with sample data...")
		if err := database.SeedData(); err != nil {
			log.Fatalf("Seeding failed: %v", err)
		}
	}

	// Health check
	if err := database.HealthCheck(); err != nil {
		log.Fatalf("Database health check failed: %v", err)
	}

	log.Println("🎉 Database setup completed successfully!")
}