package webhook

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"

	"forgerealm-auth/db"
)

// HandleWebhook processes incoming webhook events
func HandleWebhook(w http.ResponseWriter, r *http.Request) {
	// Verify webhook signature
	signature := r.Header.Get("X-Patreon-Signature")
	if !verifySignature(r, signature) {
		http.Error(w, "Invalid signature", http.StatusUnauthorized)
		return
	}

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Parse webhook event
	var event struct {
		EventType string          `json:"event_type"`
		Payload   json.RawMessage `json:"payload"`
	}

	if err := json.Unmarshal(body, &event); err != nil {
		http.Error(w, "Invalid webhook payload", http.StatusBadRequest)
		return
	}

	// Save webhook event to database
	if err := db.SaveWebhookEvent(r.Context(), event.EventType, event.Payload); err != nil {
		http.Error(w, "Failed to save webhook event", http.StatusInternalServerError)
		return
	}

	// Process webhook event based on type
	switch event.EventType {
	case "pledges:create":
		handlePledgeCreate(event.Payload)
	case "pledges:update":
		handlePledgeUpdate(event.Payload)
	case "pledges:delete":
		handlePledgeDelete(event.Payload)
	default:
		// Log unknown event type
	}

	w.WriteHeader(http.StatusOK)
}

// verifySignature verifies the webhook signature
func verifySignature(r *http.Request, signature string) bool {
	secret := os.Getenv("WEBHOOK_SECRET")
	if secret == "" {
		return false
	}

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return false
	}
	// Restore the body for later use
	r.Body = io.NopCloser(bytes.NewReader(body))

	// Calculate HMAC
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(body)
	expectedSignature := hex.EncodeToString(h.Sum(nil))

	return hmac.Equal([]byte(signature), []byte(expectedSignature))
}

// handlePledgeCreate processes pledge creation events
func handlePledgeCreate(payload json.RawMessage) {
	// TODO: Implement pledge creation handling
}

// handlePledgeUpdate processes pledge update events
func handlePledgeUpdate(payload json.RawMessage) {
	// TODO: Implement pledge update handling
}

// handlePledgeDelete processes pledge deletion events
func handlePledgeDelete(payload json.RawMessage) {
	// TODO: Implement pledge deletion handling
}
