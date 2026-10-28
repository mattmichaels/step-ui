package auth

import (
	"testing"
	"time"

	"step-ca-webui/internal/db"
)

func TestCreateSessionWithDuration(t *testing.T) {
	database, admin := setupLoginTest(t)

	for _, hours := range []int{1, 12, 24, 48, 168} {
		t.Run(time.Duration(hours).String(), func(t *testing.T) {
			duration := time.Duration(hours) * time.Hour
			before := time.Now().UTC()

			token, err := CreateSessionWithDuration(
				database.DB,
				admin.ID,
				duration,
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

			earliest := before.Add(duration)
			latest := time.Now().UTC().Add(duration)

			if session.ExpiresAt.Before(earliest) ||
				session.ExpiresAt.After(latest) {
				t.Fatalf(
					"expiration %v outside expected range %v–%v",
					session.ExpiresAt,
					earliest,
					latest,
				)
			}
		})
	}
}

func TestCreateSessionRejectsInvalidDuration(t *testing.T) {
	database, admin := setupLoginTest(t)

	for _, duration := range []time.Duration{
		-1 * time.Hour,
		0,
		30 * time.Minute,
		169 * time.Hour,
	} {
		token, err := CreateSessionWithDuration(
			database.DB,
			admin.ID,
			duration,
		)

		if err == nil || token != "" {
			t.Fatalf(
				"duration %v unexpectedly created a session",
				duration,
			)
		}
	}

	var count int64
	if err := database.DB.Model(&db.AdminSession{}).
		Count(&count).Error; err != nil {
		t.Fatal(err)
	}

	if count != 0 {
		t.Fatalf("invalid durations created %d sessions", count)
	}
}

func TestCreateSessionPreservesDefaultDuration(t *testing.T) {
	database, admin := setupLoginTest(t)

	before := time.Now().UTC()

	token, err := CreateSession(database.DB, admin.ID)
	if err != nil {
		t.Fatal(err)
	}

	var session db.AdminSession
	if err := database.DB.
		Where("token_hash = ?", sessionTokenHash(token)).
		First(&session).Error; err != nil {
		t.Fatal(err)
	}

	earliest := before.Add(SessionDuration)
	latest := time.Now().UTC().Add(SessionDuration)

	if session.ExpiresAt.Before(earliest) ||
		session.ExpiresAt.After(latest) {
		t.Fatalf(
			"default session expiration %v is incorrect",
			session.ExpiresAt,
		)
	}
}
