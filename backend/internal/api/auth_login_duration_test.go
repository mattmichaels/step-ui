package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"step-ca-webui/internal/db"
)

func TestHTTPLoginUsesConfiguredSessionDuration(t *testing.T) {
	router, database := setupAuthHTTPTest(t)

	settings := db.DefaultAuthSettings()
	settings.SessionDurationHours = 24

	if err := database.SaveAuthSettings(&settings); err != nil {
		t.Fatal(err)
	}

	before := time.Now().UTC()

	request := httptest.NewRequest(
		http.MethodPost,
		"/api/auth/login",
		strings.NewReader(
			`{"username":"testadmin","password":"CorrectPassword123!"}`,
		),
	)
	request.Header.Set("Content-Type", "application/json")

	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf(
			"expected 200, got %d: %s",
			response.Code,
			response.Body.String(),
		)
	}

	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected one cookie, got %d", len(cookies))
	}

	cookie := cookies[0]

	if cookie.MaxAge != 24*60*60 {
		t.Fatalf(
			"cookie MaxAge = %d, want %d",
			cookie.MaxAge,
			24*60*60,
		)
	}

	if !cookie.Secure || !cookie.HttpOnly ||
		cookie.SameSite != http.SameSiteStrictMode {
		t.Fatal("session cookie security attributes changed")
	}

	var sessions []db.AdminSession
	if err := database.DB.Find(&sessions).Error; err != nil {
		t.Fatal(err)
	}

	if len(sessions) != 1 {
		t.Fatalf("expected one session, got %d", len(sessions))
	}

	earliest := before.Add(24 * time.Hour)
	latest := time.Now().UTC().Add(24 * time.Hour)

	if sessions[0].ExpiresAt.Before(earliest) ||
		sessions[0].ExpiresAt.After(latest) {
		t.Fatalf(
			"database session expiration %v does not match 24 hours",
			sessions[0].ExpiresAt,
		)
	}
}

func TestHTTPLoginRejectsCorruptedAuthSettings(t *testing.T) {
	router, database := setupAuthHTTPTest(t)

	settings := db.DefaultAuthSettings()
	if err := database.SaveAuthSettings(&settings); err != nil {
		t.Fatal(err)
	}

	if err := database.DB.Model(&db.AuthSettings{}).
		Where("id = ?", 1).
		Update("requirement", "except_local").Error; err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(
		http.MethodPost,
		"/api/auth/login",
		strings.NewReader(
			`{"username":"testadmin","password":"CorrectPassword123!"}`,
		),
	)
	request.Header.Set("Content-Type", "application/json")

	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf(
			"expected 500, got %d: %s",
			response.Code,
			response.Body.String(),
		)
	}

	if len(response.Result().Cookies()) != 0 {
		t.Fatal("corrupted settings issued a session cookie")
	}

	var sessionCount int64
	if err := database.DB.Model(&db.AdminSession{}).
		Count(&sessionCount).Error; err != nil {
		t.Fatal(err)
	}

	if sessionCount != 0 {
		t.Fatalf(
			"corrupted settings created %d sessions",
			sessionCount,
		)
	}
}
