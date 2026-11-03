package mockpatreon

// forgeRealmCampaignID is the campaign auth admits members of.
const forgeRealmCampaignID = "14358641"

// otherCampaignID is a campaign auth ignores.
const otherCampaignID = "999"

// User is one fixed Patreon account. Tier is the entitled tier's title, as
// Patreon sends it; auth lowercases it into a tier code.
type User struct {
	Key          string
	PatreonID    string
	Email        string
	FirstName    string
	LastName     string
	Campaign     string // "" for no membership at all
	PatronStatus string // "" sends null
	Tier         string // "" for no entitled tier
	Note         string // shown on the authorize page
}

// Users are the fixed test accounts (AUTH-3 D3), in the order the authorize
// page lists them.
var Users = []User{
	{Key: "apprentice", PatreonID: "mock-apprentice", Email: "apprentice@mock.patreon", FirstName: "Ada", LastName: "Apprentice",
		Campaign: forgeRealmCampaignID, PatronStatus: "active_patron", Tier: "Apprentice", Note: "Active, tier apprentice"},
	{Key: "journeyman", PatreonID: "mock-journeyman", Email: "journeyman@mock.patreon", FirstName: "Jon", LastName: "Journeyman",
		Campaign: forgeRealmCampaignID, PatronStatus: "active_patron", Tier: "Journeyman", Note: "Active, tier journeyman"},
	{Key: "master", PatreonID: "mock-master", Email: "master@mock.patreon", FirstName: "Mae", LastName: "Master",
		Campaign: forgeRealmCampaignID, PatronStatus: "active_patron", Tier: "Master", Note: "Active, tier master"},
	{Key: "lapsed", PatreonID: "mock-lapsed", Email: "lapsed@mock.patreon", FirstName: "Lee", LastName: "Lapsed",
		Campaign: forgeRealmCampaignID, PatronStatus: "former_patron", Note: "Former patron, tier non_patron"},
	{Key: "declined", PatreonID: "mock-declined", Email: "declined@mock.patreon", FirstName: "Dee", LastName: "Declined",
		Campaign: forgeRealmCampaignID, PatronStatus: "declined_patron", Tier: "Master", Note: "Payment declined, still entitled to master"},
	{Key: "admin", PatreonID: "mock-admin", Email: "admin@mock.patreon", FirstName: "Avery", LastName: "Admin",
		Campaign: forgeRealmCampaignID, PatronStatus: "active_patron", Tier: "Master", Note: "Active, tier master. Gets role admin by SQL"},
	{Key: "stranger", PatreonID: "mock-stranger", Email: "stranger@mock.patreon", FirstName: "Sam", LastName: "Stranger",
		Campaign: otherCampaignID, PatronStatus: "active_patron", Tier: "Gold", Note: "Patron of another campaign only. Auth refuses"},
}

func findUser(key string) (User, bool) {
	for _, u := range Users {
		if u.Key == key {
			return u, true
		}
	}
	return User{}, false
}
