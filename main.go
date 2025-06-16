package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"forgerealm-auth/auth"
	"forgerealm-auth/db"
	"forgerealm-auth/webhook"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/joho/godotenv"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: .env file not found")
	}

	// Initialize database
	if err := db.InitDB(); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.CloseDB()

	// Create database tables
	if err := db.CreateTables(context.Background()); err != nil {
		log.Fatalf("Failed to create database tables: %v", err)
	}

	// Initialize router
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RealIP)

	// Routes
	r.Get("/", handleHome)
	r.Get("/auth/login", auth.HandlePatreonLogin)
	r.Get("/auth/callback", auth.HandlePatreonCallback)
	r.Post("/webhook", webhook.HandleWebhook)

	// Server setup
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: r,
	}

	// Server run context
	serverCtx, serverStopCtx := context.WithCancel(context.Background())

	// Listen for syscall signals for process to interrupt/quit
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		<-sig

		// Shutdown signal with grace period of 30 seconds
		shutdownCtx, _ := context.WithTimeout(serverCtx, 30*time.Second)

		go func() {
			<-shutdownCtx.Done()
			if shutdownCtx.Err() == context.DeadlineExceeded {
				log.Fatal("graceful shutdown timed out.. forcing exit.")
			}
		}()

		// Trigger graceful shutdown
		err := srv.Shutdown(shutdownCtx)
		if err != nil {
			log.Fatal(err)
		}
		serverStopCtx()
	}()

	// Run the server
	log.Printf("Server starting on port %s", port)
	err := srv.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}

	// Wait for server context to be stopped
	<-serverCtx.Done()
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Welcome to ForgeRealm Auth Service"))
}

func handlePatreonLogin(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement Patreon OAuth2 login
	w.Write([]byte("Patreon login not implemented yet"))
}

func handlePatreonCallback(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement Patreon OAuth2 callback
	w.Write([]byte("Patreon callback not implemented yet"))
}

func handleWebhook(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement webhook handler
	w.Write([]byte("Webhook handler not implemented yet"))
}
