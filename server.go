// Simple REST API using Gin, bcrypt, and JWT with in-memory storage.

package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

var (
	users = make(map[string]string) // In-memory storage: username -> hashed password

	subscriptions      = make(map[string]string) // In-memory storage: id -> targetUrl
	subscriptionsMutex sync.Mutex                // Mutex for protecting access to the subscriptions map
	// Replace with a strong, unique secret key for JWT signing
	jwtSecret = []byte("your-secret-key")
)

type RegisterRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type SigninRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

type SubscribeRequest struct {
	TargetUrl string `json:"targetUrl" binding:"required"`
}

// generateJWT generates a new JWT token for the given username.
func generateJWT(username string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour) // Token expires in 24 hours
	claims := &Claims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// parseJWT parses and validates a JWT token.
func parseJWT(tokenString string) (*Claims, error) {
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}

func register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if user already exists
	if _, exists := users[req.Username]; exists {
		c.JSON(http.StatusConflict, gin.H{"error": "user already exists"})
		return
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash password"})
		return
	}

	// Store user in in-memory map
	users[req.Username] = string(hashedPassword)

	// Generate JWT token
	token, err := generateJWT(req.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}

func signin(c *gin.Context) {
	var req SigninRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Retrieve hashed password from in-memory map
	hashedPassword, exists := users[req.Username]
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	// Compare passwords
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(req.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	// Generate JWT token
	token, err := generateJWT(req.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}

func me(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
		return
	}

	tokenString := ""
	splitHeader := strings.Split(authHeader, " ")
	if len(splitHeader) == 2 && splitHeader[0] == "Bearer" {
		tokenString = splitHeader[1]
	} else {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header format"})
		return
	}

	claims, err := parseJWT(tokenString)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return
	}

	// In this simple example, we just return the username from the token.
	// In a real application, you might fetch more user data from the storage.
	c.JSON(http.StatusOK, gin.H{"username": claims.Username})
}

func subscribe(c *gin.Context) {
	var req SubscribeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Generate a unique identifier (you might want a more robust method in production)
	id := fmt.Sprintf("%d", time.Now().UnixNano())

	// Store the target URL in the in-memory map with a mutex
	subscriptionsMutex.Lock()
	subscriptions[id] = req.TargetUrl
	subscriptionsMutex.Unlock()

	c.JSON(http.StatusOK, gin.H{"id": id})
}

func unsubscribe(c *gin.Context) {
	id := c.Param("id")

	subscriptionsMutex.Lock()
	_, exists := subscriptions[id]
	if exists {
		delete(subscriptions, id)
		subscriptionsMutex.Unlock()
		c.JSON(http.StatusOK, gin.H{"success": true})
	} else {
		subscriptionsMutex.Unlock()
		c.JSON(http.StatusNotFound, gin.H{"success": false, "message": "Subscription not found"})
	}
}

func getSampleData(c *gin.Context) {
	// Static sample data
	sampleData := []map[string]interface{}{
		{
			"email":     "sample@example.com",
			"message":   "This is a test message",
			"timestamp": 1747401180000,
		},
	}

	// Return the static data as JSON
	c.JSON(http.StatusOK, sampleData)
}

func getSubscriptions(c *gin.Context) {
	// Create a slice to hold the subscription data
	var subscriptionList []map[string]string

	// Lock the mutex while accessing the subscriptions map
	subscriptionsMutex.Lock()
	// Iterate over the subscriptions map and add each subscription to the list
	for id, targetUrl := range subscriptions {
		subscriptionList = append(subscriptionList, map[string]string{
			"id":        id,
			"targetUrl": targetUrl,
		})
	}
	subscriptionsMutex.Unlock()

	c.JSON(http.StatusOK, subscriptionList)
}

func main() {
	r := gin.Default()

	r.POST("/register", register)
	r.POST("/signin", signin)
	r.GET("/me", me)
	r.POST("/subscribe", subscribe)           // New subscribe endpoint
	r.DELETE("/subscribe/:id", unsubscribe)   // New delete endpoint
	r.GET("/sampledata", getSampleData)       // New sampledata endpoint
	r.GET("/subscriptions", getSubscriptions) // New get subscriptions endpoint

	log.Println("Server starting on :8080")
	if err := r.Run(":8081"); err != nil {
		log.Fatal("Server failed to start: ", err)
	}
}
