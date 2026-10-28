package auth

import (
	"testing"
	"time"

	"step-ca-webui/internal/db"
)

func TestSessionDurationChangePreservesExistingSessions(t *testing.T) {
	database, admin := setupLoginTest(t)

	// First login uses the original 12-hour configuration.
	firstToken, err := LoginWithDuration(
		database.DB,
		admin.Username,
		"CorrectPassword123!",
		12*time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}

	var original db.AdminSession
	if err := database.DB.
		Where("token_hash = ?", sessionTokenHash(firstToken)).
		First(&original).Error; err != nil {
		t.Fatal(err)
	}

	originalExpiration := original.ExpiresAt

	// Administrator changes the configured duration to 48 hours.
	settings := db.DefaultAuthSettings()
	settings.SessionDurationHours = 48

	if err := database.SaveAuthSettings(&settings); err != nil {
		t.Fatal(err)
	}

	// A subsequent login uses the updated configuration.
	saved, err := database.GetAuthSettings()
	if err != nil {
		t.Fatal(err)
	}

	secondToken, err := LoginWithDuration(
		database.DB,
		admin.Username,
		"CorrectPassword123!",
		time.Duration(saved.SessionDurationHours)*time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}

	var second db.AdminSession
	if err := database.DB.
		Where("token_hash = ?", sessionTokenHash(secondToken)).
		First(&second).Error; err != nil {
		t.Fatal(err)
	}

	// Reload the original session to detect accidental modifications.
	var reloaded db.AdminSession
	if err := database.DB.
		Where("token_hash = ?", sessionTokenHash(firstToken)).
		First(&reloaded).Error; err != nil {
		t.Fatal(err)
	}

	if !reloaded.ExpiresAt.Equal(originalExpiration) {
		t.Fatalf(
			"existing session expiration changed: %v -> %v",
			originalExpiration,
			reloaded.ExpiresAt,
		)
	}

	expected := time.Now().UTC().Add(48 * time.Hour)
	difference := second.ExpiresAt.Sub(expected)

	if difference < -5*time.Second || difference > 5*time.Second {
		t.Fatalf(
			"new session expiration %v does not reflect 48 hours",
			second.ExpiresAt,
		)
	}

	if !second.ExpiresAt.After(reloaded.ExpiresAt) {
		t.Fatal("new session should expire after original session")
	}
}
