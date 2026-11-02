package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"forgerealm-auth/db"
)

// Patreon webhook event types, sent in the X-Patreon-Event header.
var webhookEventTypes = map[string]bool{
	"members:create":        true,
	"members:update":        true,
	"members:delete":        true,
	"members:pledge:create": true,
	"members:pledge:update": true,
	"members:pledge:delete": true,
}

// Charge statuses that close an account (ED77). A plain "Refunded" does not.
var closingChargeStatuses = map[string]bool{
	"Refunded by Patreon": true,
	"Fraud":               true,
}

const nonPatronTier = "non_patron"

// patreonMemberWebhook is the JSON:API member document Patreon posts.
type patreonMemberWebhook struct {
	Data struct {
		ID         string `json:"id"`
		Attributes struct {
			Email                        string  `json:"email"`
			PatronStatus                 *string `json:"patron_status"`
			LastChargeDate               *string `json:"last_charge_date"`
			LastChargeStatus             *string `json:"last_charge_status"`
			CurrentlyEntitledAmountCents int     `json:"currently_entitled_amount_cents"`
		} `json:"attributes"`
		Relationships struct {
			User struct {
				Data struct {
					ID string `json:"id"`
				} `json:"data"`
			} `json:"user"`
			CurrentlyEntitledTiers struct {
				Data []struct {
					ID string `json:"id"`
				} `json:"data"`
			} `json:"currently_entitled_tiers"`
		} `json:"relationships"`
	} `json:"data"`
	Included []struct {
		Type       string `json:"type"`
		ID         string `json:"id"`
		Attributes struct {
			Title     string `json:"title"`
			FirstName string `json:"first_name"`
			LastName  string `json:"last_name"`
		} `json:"attributes"`
	} `json:"included"`
}

// verifySignature checks X-Patreon-Signature, the hex HMAC-MD5 of the body
// keyed with WEB_HOOK_SECRET (the name the deploy sets).
func verifySignature(body []byte, signature string) bool {
	secret := strings.TrimSpace(os.Getenv("WEB_HOOK_SECRET"))
	if secret == "" {
		log.Printf("ERROR: WEB_HOOK_SECRET environment variable is not set")
		return false
	}
	h := hmac.New(md5.New, []byte(secret))
	h.Write(body)
	expected := hex.EncodeToString(h.Sum(nil))
	if !hmac.Equal([]byte(signature), []byte(expected)) {
		log.Printf("ERROR: Invalid webhook signature")
		return false
	}
	return true
}

// HandleWebhook records one Patreon member webhook: the user's tier and status,
// the event, a paid charge in the credit outbox (ED76), and account closing on
// a Patreon refund or chargeback (ED77), in one transaction. A failure answers
// 500 so Patreon can retry.
func (a *PatreonAuth) HandleWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	if !verifySignature(body, r.Header.Get("X-Patreon-Signature")) {
		http.Error(w, "Invalid signature", http.StatusUnauthorized)
		return
	}

	eventType := r.Header.Get("X-Patreon-Event")
	if eventType == "" {
		http.Error(w, "Missing X-Patreon-Event header", http.StatusBadRequest)
		return
	}
	if !webhookEventTypes[eventType] {
		log.Printf("WARN: Ignoring unknown webhook event type: %s", eventType)
		w.WriteHeader(http.StatusOK)
		return
	}

	var member patreonMemberWebhook
	if err := json.Unmarshal(body, &member); err != nil {
		log.Printf("ERROR: Failed to decode %s webhook: %v", eventType, err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	rec, err := webhookRecord(eventType, member, body)
	if err != nil {
		log.Printf("ERROR: Cannot record %s webhook (member %s): %v", eventType, member.Data.ID, err)
		http.Error(w, "Invalid member data", http.StatusBadRequest)
		return
	}

	if err := a.db.RecordWebhook(r.Context(), rec); err != nil {
		log.Printf("ERROR: Failed to record %s webhook (Patreon ID: %s): %v", eventType, rec.PatreonID, err)
		http.Error(w, "Failed to record webhook", http.StatusInternalServerError)
		return
	}

	log.Printf("INFO: Recorded %s webhook (Patreon ID: %s, tier: %s, status: %s, charge: %t, close: %q)",
		eventType, rec.PatreonID, rec.TierID, rec.PatronStatus, rec.Charge != nil, rec.CloseReason)
	w.WriteHeader(http.StatusOK)
}

// webhookRecord turns a member webhook into what the database records.
func webhookRecord(eventType string, member patreonMemberWebhook, raw []byte) (db.WebhookRecord, error) {
	attrs := member.Data.Attributes
	patreonID := member.Data.Relationships.User.Data.ID
	if patreonID == "" {
		return db.WebhookRecord{}, fmt.Errorf("member has no user relationship")
	}

	rec := db.WebhookRecord{
		EventType:  eventType,
		PatreonID:  patreonID,
		Email:      attrs.Email,
		RawPayload: raw,
	}
	for _, inc := range member.Included {
		if inc.Type == "user" && inc.ID == patreonID {
			rec.GivenName = inc.Attributes.FirstName
			rec.SurName = inc.Attributes.LastName
		}
	}

	if attrs.PatronStatus != nil {
		rec.PatronStatus = *attrs.PatronStatus
	}

	tier, err := entitledTier(member)
	if err != nil {
		return db.WebhookRecord{}, err
	}
	rec.TierID = tier

	// A deleted membership has no tier, whatever the payload still lists.
	if eventType == "members:delete" || eventType == "members:pledge:delete" {
		rec.TierID = nonPatronTier
		rec.PatronStatus = "former_patron"
	}

	if attrs.LastChargeStatus != nil {
		status := *attrs.LastChargeStatus
		if closingChargeStatuses[status] {
			rec.CloseReason = status
		}
		// The charged tier is the one entitled at the charge; with none there is nothing to grant.
		if status == "Paid" && attrs.LastChargeDate != nil && tier != nonPatronTier {
			chargedAt, err := time.Parse(time.RFC3339, *attrs.LastChargeDate)
			if err != nil {
				return db.WebhookRecord{}, fmt.Errorf("parse last_charge_date %q: %w", *attrs.LastChargeDate, err)
			}
			rec.Charge = &db.Charge{
				Tier:        tier,
				ChargedAt:   chargedAt.UTC().Truncate(time.Second),
				AmountCents: attrs.CurrentlyEntitledAmountCents,
			}
		}
	}
	return rec, nil
}

// entitledTier returns the member's first entitled tier as a tier code (its
// lowercased title, as login uses), or non_patron when it has none.
func entitledTier(member patreonMemberWebhook) (string, error) {
	tiers := member.Data.Relationships.CurrentlyEntitledTiers.Data
	if len(tiers) == 0 {
		return nonPatronTier, nil
	}
	for _, inc := range member.Included {
		if inc.Type == "tier" && inc.ID == tiers[0].ID && inc.Attributes.Title != "" {
			return strings.ToLower(inc.Attributes.Title), nil
		}
	}
	return "", fmt.Errorf("entitled tier %s has no title in the payload", tiers[0].ID)
}
