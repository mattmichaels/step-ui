package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"step-ca-webui/internal/auth"
	"step-ca-webui/internal/db"
)

func setupAuthSettingsHTTPTest(t *testing.T) (*gin.Engine, *db.Database, string) {
	t.Helper()

	_, database := setupAuthHTTPTest(t)
	handlers := NewHandlers(database, nil)

	router := gin.New()
	protected := router.Group("/api")
	protected.Use(handlers.RequireAdmin())
	protected.GET("/settings/authentication", handlers.GetAuthSettings)
	protected.PUT("/settings/authentication", handlers.UpdateAuthSettings)

	token, err := auth.CreateSession(database.DB, 1)
	if err != nil {
		t.Fatal(err)
	}

	return router, database, token
}

func authSettingsRequest(
	router *gin.Engine,
	method string,
	body string,
	token string,
) *httptest.ResponseRecorder {
	request := httptest.NewRequest(
		method,
		"/api/settings/authentication",
		strings.NewReader(body),
	)
	request.Header.Set("Content-Type", "application/json")

	if token != "" {
		request.AddCookie(&http.Cookie{
			Name:  sessionCookieName,
			Value: token,
		})
	}

	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func TestAuthSettingsHTTPUnauthorized(t *testing.T) {
	router, _, _ := setupAuthSettingsHTTPTest(t)

	for _, method := range []string{http.MethodGet, http.MethodPut} {
		response := authSettingsRequest(router, method, `{}`, "")

		if response.Code != http.StatusUnauthorized {
			t.Fatalf("%s: expected 401, got %d", method, response.Code)
		}
	}
}

func TestAuthSettingsHTTPReadDefaults(t *testing.T) {
	router, _, token := setupAuthSettingsHTTPTest(t)

	response := authSettingsRequest(router, http.MethodGet, "", token)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s",
			response.Code, response.Body.String())
	}

	var settings db.AuthSettings
	if err := json.Unmarshal(response.Body.Bytes(), &settings); err != nil {
		t.Fatal(err)
	}

	if !settings.Validate() ||
		settings.Method != db.AuthMethodForms ||
		settings.Requirement != db.AuthRequirementAlways ||
		settings.SessionDurationHours != 12 {
		t.Fatalf("unexpected defaults: %+v", settings)
	}
}

func TestAuthSettingsHTTPUpdate(t *testing.T) {
	router, database, token := setupAuthSettingsHTTPTest(t)

	response := authSettingsRequest(
		router,
		http.MethodPut,
		`{"method":"forms","requirement":"always","session_duration_hours":24}`,
		token,
	)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s",
			response.Code, response.Body.String())
	}

	settings, err := database.GetAuthSettings()
	if err != nil {
		t.Fatal(err)
	}
	if settings.SessionDurationHours != 24 {
		t.Fatalf("saved duration = %d, want 24",
			settings.SessionDurationHours)
	}

	var auditCount int64
	if err := database.DB.Model(&db.AuditEvent{}).
		Where("action = ?", "admin.auth_settings.update").
		Count(&auditCount).Error; err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("audit events = %d, want 1", auditCount)
	}
}

func TestAuthSettingsHTTPRejectUnsafeConfiguration(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			name: "disable authentication",
			body: `{"method":"none","requirement":"always","session_duration_hours":12}`,
		},
		{
			name: "local bypass",
			body: `{"method":"forms","requirement":"except_local","session_duration_hours":12}`,
		},
		{
			name: "zero duration",
			body: `{"method":"forms","requirement":"always","session_duration_hours":0}`,
		},
		{
			name: "unknown field",
			body: `{"method":"forms","requirement":"always","session_duration_hours":12,"bypass":true}`,
		},
		{
			name: "multiple objects",
			body: `{"method":"forms","requirement":"always","session_duration_hours":12}{}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			router, database, token := setupAuthSettingsHTTPTest(t)

			response := authSettingsRequest(
				router, http.MethodPut, tc.body, token,
			)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s",
					response.Code, response.Body.String())
			}

			settings, err := database.GetAuthSettings()
			if err != nil {
				t.Fatal(err)
			}
			if settings.SessionDurationHours != 12 {
				t.Fatal("rejected request changed settings")
			}
		})
	}
}

func TestAuthSettingsHTTPAuditRollback(t *testing.T) {
	router, database, token := setupAuthSettingsHTTPTest(t)

	// Establish a known configuration before simulating failure.
	settings := db.DefaultAuthSettings()
	if err := database.SaveAuthSettings(&settings); err != nil {
		t.Fatal(err)
	}

	// Force audit insertion to fail inside the settings transaction.
	if err := database.DB.Exec("DROP TABLE audit_events").Error; err != nil {
		t.Fatal(err)
	}

	response := authSettingsRequest(
		router,
		http.MethodPut,
		`{"method":"forms","requirement":"always","session_duration_hours":48}`,
		token,
	)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf(
			"expected 500 when audit persistence fails, got %d: %s",
			response.Code,
			response.Body.String(),
		)
	}

	saved, err := database.GetAuthSettings()
	if err != nil {
		t.Fatal(err)
	}

	if saved.SessionDurationHours != 12 {
		t.Fatalf(
			"settings changed despite failed audit: duration = %d",
			saved.SessionDurationHours,
		)
	}
}

func TestAuthSettingsHTTPBodySizeLimit(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			name: "oversized JSON object",
			body: `{"method":"forms","requirement":"always","session_duration_hours":12,"padding":"` +
				strings.Repeat("x", 5000) + `"}`,
		},
		{
			name: "oversized trailing whitespace",
			body: `{"method":"forms","requirement":"always","session_duration_hours":12}` +
				strings.Repeat(" ", 5000),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			router, database, token := setupAuthSettingsHTTPTest(t)

			response := authSettingsRequest(
				router,
				http.MethodPut,
				tc.body,
				token,
			)

			if response.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf(
					"expected 413, got %d: %s",
					response.Code,
					response.Body.String(),
				)
			}

			var count int64
			if err := database.DB.Model(&db.AuthSettings{}).
				Count(&count).Error; err != nil {
				t.Fatal(err)
			}

			if count != 0 {
				t.Fatalf("oversized request created %d settings rows", count)
			}
		})
	}
}
