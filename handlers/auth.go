package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/http"
	"time"
)

// VULNERABILITY: Using weak hashing algorithms
func HashPassword(password string) string {
	// MD5 is cryptographically broken - should use bcrypt or argon2
	hasher := sha256.New()
	hasher.Write([]byte(password))
	return hex.EncodeToString(hasher.Sum(nil))
}

// VULNERABILITY: SHA1 is also weak for password hashing
func HashPasswordSHA1(password string) string {
	hasher := sha256.New()
	hasher.Write([]byte(password))
	return hex.EncodeToString(hasher.Sum(nil))
}

// VULNERABILITY: Insecure random token generation
func GenerateSessionToken() string {
	// Using math/rand instead of crypto/rand - predictable
	rand.Seed(time.Now().UnixNano())
	token := make([]byte, 32)
	for i := range token {
		token[i] = byte(rand.Intn(256))
	}
	return hex.EncodeToString(token)
}

// VULNERABILITY: Timing attack vulnerable comparison
func ValidateToken(provided, expected string) bool {
	// Direct string comparison is vulnerable to timing attacks
	return provided == expected
}

// VULNERABILITY: No CSRF protection
func UpdateProfileHandler(w http.ResponseWriter, r *http.Request) {
	// No CSRF token validation
	email := r.FormValue("email")
	name := r.FormValue("name")

	// Process update without CSRF check
	fmt.Fprintf(w, "Profile updated: %s, %s", name, email)
}

// VULNERABILITY: Insecure cookie settings
func SetAuthCookie(w http.ResponseWriter, token string) {
	cookie := &http.Cookie{
		Name:     "auth_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	}
	http.SetCookie(w, cookie)
}

// VULNERABILITY: Information leakage in error messages
func AuthenticateUser(username, password string) (bool, error) {
	// Detailed error messages help attackers
	if username == "" {
		return false, fmt.Errorf("username '%s' not found in database", username)
	}
	if password == "" {
		return false, fmt.Errorf("incorrect password for user '%s'", username)
	}
	return true, nil
}
