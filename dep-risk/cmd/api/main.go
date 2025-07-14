package main

import (
	"log"

	"github.com/dep-risk/dep-risk/internal/api"
	"github.com/dep-risk/dep-risk/internal/database"
)

func main() {
	log.Println("🚀 Starting Dep-Risk API Server...")

	// Load database configuration
	config := database.LoadConfigFromEnv()

	// Connect to database
	if err := database.Connect(config); err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer database.Close()

	// Run migrations
	if err := database.Migrate(); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	// Create and start API server
	server := api.NewServer()
	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}