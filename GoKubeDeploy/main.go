package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
	"github.com/sirupsen/logrus"
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/store/memory"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type HealthStatus struct {
    Status  string `json:"status"`
    Message string `json:"message,omitempty"`
}

type Claims struct {
    UserID string `json:"user_id"`
    Email  string `json:"email"`
    Role   string `json:"role"`
    jwt.StandardClaims
}

type AppError struct {
    Message string `json:"message"`
    Code    int    `json:"code"`
}

func (e *AppError) Error() string {
    return e.Message
}

var db *sql.DB
var jwtKey = []byte(os.Getenv("JWT_SECRET"))

var oauthConfig = &oauth2.Config{
    ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
    ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
    RedirectURL:  os.Getenv("GOOGLE_REDIRECT_URL"),
    Endpoint:     google.Endpoint,
    Scopes:       []string{"profile", "email"},
}

func main() {
    var err error
    db, err = sql.Open("postgres", os.Getenv("DATABASE_URL"))
    if err != nil {
        logrus.WithFields(logrus.Fields{
            "error": err,
        }).Fatal("Failed to open database connection")
    }
    defer db.Close()

    r := gin.Default()

    // Define routes
    r.GET("/login", loginHandler)
    r.GET("/callback", callbackHandler)
    r.GET("/healthz", AuthMiddleware(), healthCheckHandler)
    r.GET("/protected", AuthMiddleware(), protectedEndpoint)

    // Start the server
    if err := r.Run(":8080"); err != nil {
        logrus.WithFields(logrus.Fields{
            "error": err,
        }).Fatal("Could not start server")
    }
}

func AuthMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        authHeader := c.GetHeader("Authorization")
        if authHeader == "" {
            c.AbortWithStatusJSON(http.StatusUnauthorized, &AppError{Message: "Authorization header missing", Code: http.StatusUnauthorized})
            return
        }
        tokenString := strings.Replace(authHeader, "Bearer ", "", 1)
        claims, err := VerifyJWT(tokenString)
        if err != nil {
            c.AbortWithStatusJSON(http.StatusUnauthorized, &AppError{Message: err.Error(), Code: http.StatusUnauthorized})
            return
        }
        c.Set("claims", claims)
        c.Next()
    }
}

func loginHandler(c *gin.Context) {
    rateLimit := os.Getenv("RATE_LIMIT")
    if rateLimit == "" {
        rateLimit = "10-M" // Default rate limit
    }
    rate, err := limiter.NewRateFromFormatted(rateLimit)
    if err != nil {
        logrus.WithFields(logrus.Fields{
            "error": err,
        }).Error("Failed to create rate limiter")
        c.AbortWithStatusJSON(http.StatusInternalServerError, &AppError{Message: "Internal server error", Code: http.StatusInternalServerError})
        return
    }
    store := memory.NewStore()
    instance := limiter.New(store, rate)
    ctx := context.Background()
    key := c.ClientIP()
    limit, err := instance.Get(ctx, key)
    if err != nil {
        logrus.WithFields(logrus.Fields{
            "error": err,
        }).Error("Failed to get rate limit")
        c.AbortWithStatusJSON(http.StatusInternalServerError, &AppError{Message: "Internal server error", Code: http.StatusInternalServerError})
        return
    }
    if limit.Reached {
        c.AbortWithStatusJSON(http.StatusTooManyRequests, &AppError{Message: "Too many requests", Code: http.StatusTooManyRequests})
        return
    }

    url := oauthConfig.AuthCodeURL("state", oauth2.AccessTypeOffline)
    c.Redirect(http.StatusTemporaryRedirect, url)
}

func callbackHandler(c *gin.Context) {
    code := c.Query("code")
    if code == "" {
        c.AbortWithStatusJSON(http.StatusBadRequest, &AppError{Message: "Missing code parameter", Code: http.StatusBadRequest})
        return
    }

    // Input sanitization
    code = strings.TrimSpace(code)

    token, err := oauthConfig.Exchange(context.Background(), code)
    if err != nil {
        logrus.WithFields(logrus.Fields{
            "error": err,
        }).Error("OAuth2 token exchange failed")
        c.AbortWithStatusJSON(http.StatusInternalServerError, &AppError{Message: "OAuth2 authentication failed", Code: http.StatusInternalServerError})
        return
    }

    client := oauthConfig.Client(context.Background(), token)
    resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
    if err != nil {
        logrus.WithFields(logrus.Fields{
            "error": err,
        }).Error("Failed to get user info")
        c.AbortWithStatusJSON(http.StatusInternalServerError, &AppError{Message: "Failed to get user info", Code: http.StatusInternalServerError})
        return
    }
    defer resp.Body.Close()

    var userInfo struct {
        ID       string `json:"sub"`
        Email    string `json:"email"`
        Name     string `json:"name"`
        Picture  string `json:"picture"`
        Verified bool   `json:"email_verified"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
        logrus.WithFields(logrus.Fields{
            "error": err,
        }).Error("Failed to decode user info")
        c.AbortWithStatusJSON(http.StatusInternalServerError, &AppError{Message: "Failed to decode user info", Code: http.StatusInternalServerError})
        return
    }

    jwtToken, err := GenerateJWT(userInfo.ID, userInfo.Email, "user")
    if err != nil {
        logrus.WithFields(logrus.Fields{
            "error": err,
        }).Error("Failed to generate JWT")
        c.AbortWithStatusJSON(http.StatusInternalServerError, &AppError{Message: "Failed to generate JWT", Code: http.StatusInternalServerError})
        return
    }

    c.JSON(http.StatusOK, gin.H{"token": jwtToken})
}

func protectedEndpoint(c *gin.Context) {
    claims := c.MustGet("claims").(*Claims)
    if claims.Role != "admin" {
        c.AbortWithStatusJSON(http.StatusForbidden, &AppError{Message: "Access denied", Code: http.StatusForbidden})
        return
    }
    c.JSON(http.StatusOK, gin.H{"message": "Access granted", "email": claims.Email, "role": claims.Role})
}

func healthCheckHandler(c *gin.Context) {
    // Aquí puedes agregar la lógica de comprobación de salud
    // Por ejemplo, verificar la conexión a una base de datos o un servicio externo
    // Si todo está bien, devuelve un código de estado 200
    status := HealthStatus{Status: "OK"}

    // Simular un fallo si la variable de entorno SIMULAR_FALLO está presente
    if os.Getenv("SIMULAR_FALLO") != "" {
        status = HealthStatus{Status: "ERROR", Message: "Error simulado"}
        c.JSON(http.StatusInternalServerError, status) // Cambiar el código de estado
        return
    }

    c.JSON(http.StatusOK, status)

    // Usar logrus para registrar el health check
    logrus.Info("Health check realizado")
}

func GenerateJWT(userID, email, role string) (string, error) {
    expirationTime := time.Now().Add(5 * time.Minute)
    claims := &Claims{
        UserID: userID,
        Email:  email,
        Role:   role,
        StandardClaims: jwt.StandardClaims{
            ExpiresAt: expirationTime.Unix(),
            IssuedAt:  time.Now().Unix(),
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := token.SignedString(jwtKey)
    if err != nil {
        return "", &AppError{Message: "Error generating JWT", Code: http.StatusInternalServerError}
    }
    return tokenString, nil
}

func VerifyJWT(tokenString string) (*Claims, error) {
    token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, &AppError{Message: fmt.Sprintf("unexpected signing method: %v", token.Header["alg"]), Code: http.StatusUnauthorized}
        }
        return jwtKey, nil
    })
    if err != nil {
        return nil, &AppError{Message: "Invalid token", Code: http.StatusUnauthorized}
    }
    if !token.Valid {
        return nil, &AppError{Message: "Invalid token", Code: http.StatusUnauthorized}
    }
    return token.Claims.(*Claims), nil
}
