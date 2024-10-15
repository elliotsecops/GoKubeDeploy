package main

import (
    "database/sql"
    "encoding/json"
    "net/http"
    "os"

    "github.com/gin-gonic/gin"
    "github.com/google/uuid"
    "github.com/sirupsen/logrus"
    "github.com/spf13/viper" // for reading config and version from file
    _ "github.com/lib/pq"
)

type HealthStatus struct {
    Status  string `json:"status"`
    Message string `json:"message,omitempty"`
}

type AppError struct {
    Message string `json:"message"`
    Code    int    `json:"code"`
}

func (e *AppError) Error() string {
    return e.Message
}

var db *sql.DB
var appVersion string

func main() {
    viper.AutomaticEnv() // Read environment variables
    appVersion = viper.GetString("APP_VERSION")

    logrus.SetFormatter(&logrus.JSONFormatter{})
    logrus.AddHook(contextHook{appVersion: appVersion})

    var err error
    db, err = sql.Open("postgres", os.Getenv("DATABASE_URL"))
    if err != nil {
        logrus.WithFields(logrus.Fields{
            "error": err,
            "url":   os.Getenv("DATABASE_URL"),
        }).Fatal("Failed to open database connection")
    }
    defer db.Close()

    r := setupRouter()
    if err := r.Run(":8080"); err != nil {
        logrus.WithFields(logrus.Fields{
            "error": err,
        }).Fatal("Could not start server")
    }
}

// Middleware to add request IDs to the context
func requestIDMiddleware(c *gin.Context) {
    requestID := uuid.New().String()
    c.Set("requestID", requestID)
    c.Next()
}

func checkDatabaseConnection() error {
    err := db.Ping()
    if err != nil {
        return &AppError{Message: "Database connection failed", Code: http.StatusInternalServerError}
    }
    return nil
}

func healthCheckHandler(c *gin.Context) {
    requestID := c.MustGet("requestID").(string)
    ctx := logrus.WithFields(logrus.Fields{"request_id": requestID})

    // Check database connection
    err := checkDatabaseConnection()
    if err != nil {
        ctx.WithError(err).WithField("database_url", os.Getenv("DATABASE_URL")).Error("Database check failed")
        c.JSON(err.(*AppError).Code, gin.H{"status": "ERROR", "message": err.Error()})
        return
    }

    // Simulate a failure if the environment variable SIMULAR_FALLO is present
    simulatedError := os.Getenv("SIMULAR_FALLO")
    if simulatedError != "" {
        status := HealthStatus{Status: "ERROR", Message: simulatedError}
        if err := c.JSON(http.StatusInternalServerError, status); err != nil {
            ctx.WithError(err).Error("Failed to encode JSON response")
            return
        }
        ctx.WithFields(logrus.Fields{"status": status.Status, "simulated_error": simulatedError}).Warn("Simulated health check failure")
        return
    }

    status := HealthStatus{Status: "OK"}
    if err := c.JSON(http.StatusOK, status); err != nil {
        ctx.WithError(err).Error("Failed to encode JSON response")
        return
    }
    ctx.WithField("status", status.Status).Info("Health check performed")
}

func setupRouter() *gin.Engine {
    r := gin.Default()
    r.Use(requestIDMiddleware)
    r.GET("/healthz", healthCheckHandler)
    return r
}

// contextHook is a custom Logrus hook to add context to logs
type contextHook struct {
    appVersion string
}

func (h contextHook) Levels() []logrus.Level {
    return logrus.AllLevels
}

func (h contextHook) Fire(entry *logrus.Entry) error {
    entry.Data["app_version"] = h.appVersion
    return nil
}
