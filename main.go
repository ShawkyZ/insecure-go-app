package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"gopkg.in/yaml.v2"
)

var db *sql.DB

// Config holds application configuration
type Config struct {
	DatabaseURL string `yaml:"database_url"`
	SecretKey   string `yaml:"secret_key"`
	Debug       bool   `yaml:"debug"`
}

// User represents a user in the system
type User struct {
	ID       int
	Username string
	Password string // Vulnerability: storing plain text passwords
	Email    string
	Role     string
}

// VULNERABILITY 1: Hardcoded credentials
const (
	AdminPassword = "admin123"
	APIKey        = "sk-1234567890abcdef"
	DBPassword    = os.Getenv("DB_PASSWORD")
)

func main() {
	// VULNERABILITY 2: Weak secret key for JWT
	secretKey := []byte("secret")

	r := mux.NewRouter()

	// Routes with various vulnerabilities
	r.HandleFunc("/login", loginHandler).Methods("POST")
	r.HandleFunc("/user", getUserHandler).Methods("GET")
	r.HandleFunc("/search", searchHandler).Methods("GET")
	r.HandleFunc("/exec", execHandler).Methods("POST")
	r.HandleFunc("/upload", uploadHandler).Methods("POST")
	r.HandleFunc("/template", templateHandler).Methods("GET")
	r.HandleFunc("/file", fileHandler).Methods("GET")
	r.HandleFunc("/redirect", redirectHandler).Methods("GET")
	r.HandleFunc("/config", configHandler).Methods("GET")
	r.HandleFunc("/debug", debugHandler).Methods("GET")

	fmt.Println("Server starting on :8080")
	fmt.Printf("Using secret key: %s\n", secretKey)

	// VULNERABILITY 3: No TLS/HTTPS
	log.Fatal(http.ListenAndServe(":8080", r))
}

// VULNERABILITY 4: SQL Injection
func getUserHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")

	// Direct string concatenation in SQL query - SQL Injection vulnerability
	query := "SELECT id, username, email FROM users WHERE username = '" + username + "'"

	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		rows.Scan(&u.ID, &u.Username, &u.Email)
		users = append(users, u)
	}

	fmt.Fprintf(w, "Users: %v", users)
}

// VULNERABILITY 5: Command Injection
func execHandler(w http.ResponseWriter, r *http.Request) {
	cmd := r.FormValue("cmd")

	// Direct execution of user input - Command Injection vulnerability
	output, err := exec.Command("sh", "-c", cmd).Output()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write(output)
}

// VULNERABILITY 6: Path Traversal
func fileHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("name")

	// No sanitization of file path - Path Traversal vulnerability
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Write(content)
}

// VULNERABILITY 7: Cross-Site Scripting (XSS)
func searchHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")

	// Directly reflecting user input without escaping - XSS vulnerability
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<html><body><h1>Search Results for: %s</h1></body></html>", query)
}

// VULNERABILITY 8: Server-Side Template Injection
func templateHandler(w http.ResponseWriter, r *http.Request) {
	userTemplate := r.URL.Query().Get("template")

	// Parsing user-controlled template - SSTI vulnerability
	tmpl, err := template.New("user").Parse(userTemplate)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	tmpl.Execute(w, nil)
}

// VULNERABILITY 9: Insecure file upload
func uploadHandler(w http.ResponseWriter, r *http.Request) {
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	// No validation of file type or content
	content, _ := ioutil.ReadAll(file)

	// Saving file with original name without sanitization
	uploadPath := filepath.Join("/uploads", header.Filename)
	ioutil.WriteFile(uploadPath, content, 0777) // Insecure permissions

	fmt.Fprintf(w, "File uploaded to: %s", uploadPath)
}

// VULNERABILITY 10: Open Redirect
func redirectHandler(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")

	// Redirecting to user-supplied URL without validation
	http.Redirect(w, r, url, http.StatusFound)
}

// VULNERABILITY 11: Insecure JWT validation
func loginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	// VULNERABILITY: Weak comparison and no rate limiting
	if username == "admin" && password == AdminPassword {
		// Using vulnerable jwt-go library with weak secret
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"username": username,
			"role":     "admin",
		})

		// VULNERABILITY: Weak secret key
		tokenString, _ := token.SignedString([]byte("secret"))

		fmt.Fprintf(w, "Token: %s", tokenString)
	} else {
		// VULNERABILITY: Information disclosure
		http.Error(w, "Invalid username or password for user: "+username, http.StatusUnauthorized)
	}
}

// VULNERABILITY 12: Sensitive data exposure
func configHandler(w http.ResponseWriter, r *http.Request) {
	config := Config{
		DatabaseURL: DBPassword,
		SecretKey:   APIKey,
		Debug:       true,
	}

	// Exposing sensitive configuration
	data, _ := yaml.Marshal(config)
	w.Write(data)
}

// VULNERABILITY 13: Debug endpoint exposed
func debugHandler(w http.ResponseWriter, r *http.Request) {
	// Exposing environment variables
	for _, env := range os.Environ() {
		fmt.Fprintln(w, env)
	}
}

// VULNERABILITY 14: Insecure random number generation
func generateToken() string {
	// Using predictable values instead of crypto/rand
	return fmt.Sprintf("%d", os.Getpid())
}

// VULNERABILITY 15: Insecure deserialization with yaml
func loadConfig(data []byte) (*Config, error) {
	var config Config
	// yaml.Unmarshal can be vulnerable to deserialization attacks
	err := yaml.Unmarshal(data, &config)
	return &config, err
}
