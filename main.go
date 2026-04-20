package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"

	"pfm_cp_registry_page/backend/handlers"
	"pfm_cp_registry_page/backend/middleware"
	"pfm_cp_registry_page/backend/models"
)

func main() {
	// Инициализация конфигурации
	port := getEnv("PORT", "3000") // Важно: для AI Studio используем 3000
	jwtSecret := getEnv("JWT_SECRET", "change-me-in-production")
	dbPath := getEnv("DB_PATH", "./app.db")

	// Инициализация БД
	db, err := models.InitDB(dbPath)
	if err != nil {
		log.Fatalf("failed to initialize database: %v", err)
	}
	defer db.Close()

	userModel := models.NewUserModel(db)
	authHandler := handlers.NewAuthHandler(userModel, []byte(jwtSecret))
	authMiddleware := middleware.NewAuthMiddleware([]byte(jwtSecret))

	mux := http.NewServeMux()

	// API Маршруты
	mux.HandleFunc("POST /api/register", authHandler.Register)
	mux.HandleFunc("POST /api/login", authHandler.Login)
	mux.Handle("GET /api/profile", authMiddleware.Auth(http.HandlerFunc(authHandler.Profile)))

	// Статика и HTML маршруты
	// 1. Лендинг по корневому маршруту
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join("static", "index.html"))
	})

	// 2. Страницы авторизации
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join("static", "auth", "index.html"))
	})
	mux.HandleFunc("GET /register", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join("static", "auth", "register.html"))
	})
	mux.HandleFunc("GET /profile", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join("static", "auth", "profile.html"))
	})

	// 3. Общая статика (imgs, js, css)
	mux.Handle("/imgs/", http.FileServer(http.Dir("static")))
	mux.Handle("/css/", http.FileServer(http.Dir("static/auth")))
	mux.Handle("/js/", http.FileServer(http.Dir("static/auth")))
	
	// Обработка статики на случай обращения через /static/
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	handler := withCORS(mux)

	log.Printf("Server is running on http://localhost:%s", port)
	if err := http.ListenAndServe(":"+port, handler); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}

func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}
