package main

import (
	"floaty/auth"
	"floaty/handlers"
	"floaty/middleware"
	"log"
	"net/http"
	"os"
	"strconv"
)

func main() {
	// Initialize session storage
	auth.InitSessions()

	// Check if running in no-auth mode
	noAuth := os.Getenv("FLOATY_NO_AUTH") == "true"
	if noAuth {
		log.Println("Warning: Running in NO AUTH mode. Application is publicly accessible!")
	}

	// Load credentials from environment or use defaults
	appUsername := os.Getenv("FLOATY_USERNAME")
	if appUsername == "" {
		appUsername = "admin"
		if !noAuth {
			log.Println("Warning: Using default username 'admin'. Set FLOATY_USERNAME environment variable for production.")
		}
	}

	appPassword := os.Getenv("FLOATY_PASSWORD")
	if appPassword == "" {
		appPassword = "floaty"
		if !noAuth {
			log.Println("Warning: Using default password 'floaty'. Set FLOATY_PASSWORD environment variable for production.")
		}
	}

	// Load cookie max age from environment or use default (3 days)
	cookieMaxAge := 86400 * 3 // 3 days in seconds
	if maxAgeStr := os.Getenv("FLOATY_COOKIE_MAX_AGE"); maxAgeStr != "" {
		if maxAge, err := strconv.Atoi(maxAgeStr); err == nil && maxAge > 0 {
			cookieMaxAge = maxAge
			log.Printf("Using cookie max age: %d seconds", cookieMaxAge)
		} else {
			log.Printf("Warning: Invalid FLOATY_COOKIE_MAX_AGE value '%s', using default 3 days", maxAgeStr)
		}
	}

	// Initialize handlers with configuration
	handlers.InitHandlers(handlers.Config{
		Username:     appUsername,
		Password:     appPassword,
		CookieMaxAge: cookieMaxAge,
		NoAuth:       noAuth,
	})

	mux := http.NewServeMux()

	// Static files (no auth required)
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	if noAuth {
		// No authentication - all routes are public
		mux.HandleFunc("GET /{$}", handlers.ServeIndex)
		mux.HandleFunc("POST /api/trackers/create", handlers.CreateTracker)
		mux.HandleFunc("POST /api/trackers/delete", handlers.DeleteTracker)

		// Tracker routes with slug validation
		mux.HandleFunc("GET /{slug}", middleware.WrapWithSlugValidation(handlers.ServeTracker))

		// API routes with slug validation
		mux.HandleFunc("GET /api/{slug}/total", middleware.WrapWithSlugValidation(handlers.GetTotal))
		mux.HandleFunc("GET /api/{slug}/events", middleware.WrapWithSlugValidation(handlers.GetEvents))
		mux.HandleFunc("POST /api/{slug}/add", middleware.WrapWithSlugValidation(handlers.AddValue))
		mux.HandleFunc("POST /api/{slug}/subtract", middleware.WrapWithSlugValidation(handlers.SubtractValue))
		mux.HandleFunc("POST /api/{slug}/delete", middleware.WrapWithSlugValidation(handlers.DeleteEvent))
		mux.HandleFunc("POST /api/{slug}/edit", middleware.WrapWithSlugValidation(handlers.EditEvent))
	} else {
		// Authentication enabled
		mux.HandleFunc("GET /login", handlers.ServeLogin)
		mux.HandleFunc("POST /login", handlers.HandleLogin)

		// Protected routes
		mux.HandleFunc("GET /{$}", middleware.WithAuth(handlers.ServeIndex, noAuth))
		mux.HandleFunc("POST /api/trackers/create", middleware.WithAuth(handlers.CreateTracker, noAuth))
		mux.HandleFunc("POST /api/trackers/delete", middleware.WithAuth(handlers.DeleteTracker, noAuth))

		// Tracker routes with slug validation and auth
		mux.HandleFunc("GET /{slug}", middleware.WithAuth(middleware.WrapWithSlugValidation(handlers.ServeTracker), noAuth))

		// API routes with slug validation and auth
		mux.HandleFunc("GET /api/{slug}/total", middleware.WithAuth(middleware.WrapWithSlugValidation(handlers.GetTotal), noAuth))
		mux.HandleFunc("GET /api/{slug}/events", middleware.WithAuth(middleware.WrapWithSlugValidation(handlers.GetEvents), noAuth))
		mux.HandleFunc("POST /api/{slug}/add", middleware.WithAuth(middleware.WrapWithSlugValidation(handlers.AddValue), noAuth))
		mux.HandleFunc("POST /api/{slug}/subtract", middleware.WithAuth(middleware.WrapWithSlugValidation(handlers.SubtractValue), noAuth))
		mux.HandleFunc("POST /api/{slug}/delete", middleware.WithAuth(middleware.WrapWithSlugValidation(handlers.DeleteEvent), noAuth))
		mux.HandleFunc("POST /api/{slug}/edit", middleware.WithAuth(middleware.WrapWithSlugValidation(handlers.EditEvent), noAuth))
	}

	// Wrap with logging middleware
	handler := middleware.LoggingMiddleware(mux)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server starting on port %s", port)
	if err := http.ListenAndServe(":"+port, handler); err != nil {
		log.Fatal(err)
	}
}

