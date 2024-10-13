package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/sirupsen/logrus"
)

type HealthStatus struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

var jwtKey = []byte("your_secret_key")

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Authorization token not provided", http.StatusUnauthorized)
			return
		}

		tokenString = strings.Replace(tokenString, "Bearer ", "", 1)
		claims := &jwt.StandardClaims{}

		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		if !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	// Aquí puedes agregar la lógica de comprobación de salud
	// Por ejemplo, verificar la conexión a una base de datos o un servicio externo
	// Si todo está bien, devuelve un código de estado 200
	status := HealthStatus{Status: "OK"}

	// Simular un fallo si la variable de entorno SIMULAR_FALLO está presente
	if os.Getenv("SIMULAR_FALLO") != "" {
		status = HealthStatus{Status: "ERROR", Message: "Error simulado"}
		w.WriteHeader(http.StatusInternalServerError) // Cambiar el código de estado
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)

	// Usar logrus para registrar el health check
	logrus.Info("Health check realizado")
}

func main() {
	http.Handle("/healthz", authMiddleware(http.HandlerFunc(healthCheckHandler)))
	log.Println("Starting health check server on port 8080...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Could not start server: %s\n", err)
	}
}
