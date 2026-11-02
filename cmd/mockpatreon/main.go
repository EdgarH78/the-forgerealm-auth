// Command mockpatreon runs the mock Patreon for local development (AUTH-3).
package main

import (
	"log"
	"net/http"
	"os"
	"strings"

	"forgerealm-auth/mockpatreon"
)

func envOr(name, def string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return def
}

func main() {
	port := envOr("PORT", "8090")
	s := mockpatreon.NewServer(envOr("PATREON_CLIENT_ID", "mock-client-id"), envOr("PATREON_CLIENT_SECRET", "mock-client-secret"))
	log.Printf("INFO: Mock Patreon listening on :%s with %d test users", port, len(mockpatreon.Users))
	log.Fatal(http.ListenAndServe(":"+port, s.Handler()))
}
