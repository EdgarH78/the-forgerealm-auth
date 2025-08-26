package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"forgerealm-auth/auth"
	"forgerealm-auth/db"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
)

func main() {
	log.Printf("INFO: Starting ForgeRealm Auth Service")

	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Printf("WARN: .env file not found: %v", err)
	} else {
		log.Printf("INFO: Successfully loaded .env file")
	}

	PATREON_REDIRECT_URL := strings.TrimSpace(os.Getenv("PATREON_REDIRECT_URL"))
	if PATREON_REDIRECT_URL == "" {
		PATREON_REDIRECT_URL = "https://theforgerealm.com/auth/callback"
	}

	patreonOAuthConfig := &oauth2.Config{
		ClientID:     strings.TrimSpace(os.Getenv("PATREON_CLIENT_ID")),
		ClientSecret: strings.TrimSpace(os.Getenv("PATREON_CLIENT_SECRET")),
		RedirectURL:  PATREON_REDIRECT_URL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://www.patreon.com/oauth2/authorize",
			TokenURL: "https://www.patreon.com/api/oauth2/token",
		},
		Scopes: []string{"identity", "identity[email]", "identity.memberships"},
	}

	// Initialize database
	log.Printf("INFO: Initializing database connection")
	db := db.PostgresDB{}
	if err := db.InitDB(); err != nil {
		log.Fatalf("ERROR: Failed to initialize database: %v", err)
	}
	defer db.CloseDB()

	patreonAuth := auth.NewPatreonAuth(&db, patreonOAuthConfig)
	log.Printf("INFO: Initialized Patreon authentication handler")

	tokenLogin := auth.NewTokenLogin(&db)
	log.Printf("INFO: Initialized token login handler")

	// Initialize router
	log.Printf("INFO: Setting up HTTP router and middleware")
	r := router(patreonAuth, tokenLogin)
	// Server setup
	port := strings.TrimSpace(os.Getenv("PORT"))
	if port == "" {
		port = "8080"
		log.Printf("INFO: Using default port 8080")
	} else {
		log.Printf("INFO: Using port %s from environment", port)
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
		log.Printf("INFO: Received shutdown signal, starting graceful shutdown")

		// Shutdown signal with grace period of 30 seconds
		shutdownCtx, shutdownCancel := context.WithTimeout(serverCtx, 30*time.Second)
		defer shutdownCancel()

		go func() {
			<-shutdownCtx.Done()
			if shutdownCtx.Err() == context.DeadlineExceeded {
				log.Fatal("ERROR: Graceful shutdown timed out, forcing exit")
			}
		}()

		// Trigger graceful shutdown
		err := srv.Shutdown(shutdownCtx)
		if err != nil {
			log.Printf("ERROR: Error during server shutdown: %v", err)
			log.Fatal(err)
		}
		log.Printf("INFO: Server shutdown completed successfully")
		serverStopCtx()
	}()

	// Run the server
	log.Printf("INFO: Server starting on port %s", port)
	err := srv.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		log.Printf("ERROR: Server error: %v", err)
		log.Fatal(err)
	}

	// Wait for server context to be stopped
	<-serverCtx.Done()
	log.Printf("INFO: Server context stopped, application exiting")
}

func isAllowedOrigin(origin string) bool {
	// Allow localhost (dev) and any HTTP(S) origin (you can tighten later)
	return strings.HasPrefix(origin, "http://localhost:") ||
		strings.HasPrefix(origin, "http://127.0.0.1:") ||
		strings.HasPrefix(origin, "https://") ||
		strings.HasPrefix(origin, "http://")
}

func router(patreonAuth *auth.PatreonAuth, tokenLogin *auth.TokenLogin) http.Handler {
	r := chi.NewRouter()

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins: []string{}, // use AllowOriginFunc instead
		AllowOriginFunc: func(r *http.Request, origin string) bool {
			return isAllowedOrigin(origin)
		},
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Requested-With", "Accept-Language"},
		ExposedHeaders:   []string{"Set-Cookie"},
		AllowCredentials: true,
		MaxAge:           600,
	}))

	// Ensure caches vary by Origin
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Add("Vary", "Origin")
			next.ServeHTTP(w, req)
		})
	})

	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Optional CSRF protection for cookie-based auth
	// r.Use(csrfProtect)

	// Routes
	r.Get("/", handleHome)
	r.Get("/healthz", handleHealthz)
	r.Get("/auth/login", patreonAuth.HandleLogin)
	r.Get("/auth/callback", patreonAuth.HandleCallback)
	r.Post("/auth/webhook", patreonAuth.HandleWebhook)
	r.Post("/auth/refresh", patreonAuth.HandleRefresh)
	r.Get("/auth/status", patreonAuth.HandleAuthStatus)
	r.Post("/auth/token/start", tokenLogin.StartTokenLogin)
	r.Get("/auth/token/status", tokenLogin.CheckTokenStatus)

	return r
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	if _, err := w.Write([]byte("Welcome to ForgeRealm Auth Service")); err != nil {
		log.Printf("ERROR: Failed to write response: %v", err)
	}
}

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	if _, err := w.Write([]byte("OK")); err != nil {
		log.Printf("ERROR: Failed to write response: %v", err)
	}
}
