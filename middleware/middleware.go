package middleware

import (
	"floaty/auth"
	"floaty/models"
	"floaty/storage"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

// LoggingMiddleware logs HTTP requests
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

// WithAuth wraps a handler with authentication check
func WithAuth(handler http.HandlerFunc, noAuth bool) http.HandlerFunc {
	if noAuth {
		return handler
	}
	
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("floaty_session")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		if !auth.IsValidSession(cookie.Value) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		handler(w, r)
	}
}

// WrapWithSlugValidation wraps a handler with slug validation
func WrapWithSlugValidation(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slug := r.PathValue("slug")

		if !models.IsValidSlug(slug) {
			http.Error(w, "Invalid slug format", http.StatusBadRequest)
			return
		}

		logFile := storage.GetLogFile(slug)
		if _, err := os.Stat(logFile); os.IsNotExist(err) {
			serve404(w)
			return
		}

		handler(w, r)
	}
}

func serve404(w http.ResponseWriter) {
	file, err := os.Open("templates/404.html")
	if err != nil {
		http.Error(w, "404 - Page Not Found", http.StatusNotFound)
		return
	}
	defer file.Close()

	w.WriteHeader(http.StatusNotFound)
	w.Header().Set("Content-Type", "text/html")
	io.Copy(w, file)
}
