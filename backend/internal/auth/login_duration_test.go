package auth

import (
	"testing"
	"time"

	"step-ca-webui/internal/db"
)

func TestLoginWithDuration(t *testing.T) {
	database, admin := setupLoginTest(t)

	before := time.Now().UTC()

	token, err := LoginWithDuration(
		database.DB,
		admin.Username,
		"CorrectPassword123!",
		24*time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}

	var session db.AdminSession
	if err := database.DB.
		Where("token_hash = ?", sessionTokenHash(token)).
		First(&session).Error; err != nil {
		t.Fatal(err)
	}

	earliest := before.Add(24 * time.Hour)
	latest := time.Now().UTC().Add(24 * time.Hour)

	if session.ExpiresAt.Before(earliest) ||
		session.ExpiresAt.After(latest) {
		t.Fatalf(
			"session expiration %v outside expected range",
			session.ExpiresAt,
		)
	}

	var auditCount int64
	if err := database.DB.Model(&db.AuditEvent{}).
		Where("action = ?", "admin.login").
		Count(&auditCount).Error; err != nil {
		t.Fatal(err)
	}

	if auditCount != 1 {
		t.Fatalf("login audit events = %d, want 1", auditCount)
	}
}

func TestLoginWithDurationRejectsInvalidDuration(t *testing.T) {
	database, admin := setupLoginTest(t)

	for _, duration := range []time.Duration{
		0,
		-1 * time.Hour,
		30 * time.Minute,
		169 * time.Hour,
	} {
		token, err := LoginWithDuration(
			database.DB,
			admin.Username,
			"CorrectPassword123!",
			duration,
		)

		if err == nil || token != "" {
			t.Fatalf(
				"invalid duration %v unexpectedly succeeded",
				duration,
			)
		}
	}

	var sessionCount int64
	if err := database.DB.Model(&db.AdminSession{}).
		Count(&sessionCount).Error; err != nil {
		t.Fatal(err)
	}

	if sessionCount != 0 {
		t.Fatalf(
			"invalid durations created %d sessions",
			sessionCount,
		)
	}
}
