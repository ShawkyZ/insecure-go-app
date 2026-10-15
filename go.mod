module insecure-go-app

go 1.19

require (
	// jwt-go migrated to its maintained successor (fix for CVE-2020-26160)

	// VULNERABLE: MySQL driver - older version
	github.com/go-sql-driver/mysql v1.4.0

	// VULNERABLE: Old version of gorilla/mux
	github.com/gorilla/mux v1.7.0

	// VULNERABLE: yaml.v2 has known vulnerabilities
	gopkg.in/yaml.v2 v2.2.2
)

require github.com/golang-jwt/jwt/v4 v4.5.2

require google.golang.org/appengine v1.6.8 // indirect
