package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"step-ca-webui/internal/auth"
	"step-ca-webui/internal/db"
)

func TestChangeAdminPasswordHTTP(t *testing.T) {
	gin.SetMode(gin.TestMode)

	database, err := db.NewDatabase(
		filepath.Join(t.TempDir(), "change-password-http.db"),
	)
	if err != nil {
		t.Fatal(err)
	}

	sqlDB, err := database.DB.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	const oldPassword = "CorrectPassword123!"
	const newPassword = "NewSecurePassword456!"

	hash, err := auth.HashPassword(oldPassword)
	if err != nil {
		t.Fatal(err)
	}

	admin := db.AdminUser{
		Username:     "admin",
		PasswordHash: hash,
	}
	if err := database.DB.Create(&admin).Error; err != nil {
		t.Fatal(err)
	}

	currentToken, err := auth.Login(database.DB, admin.Username, oldPassword)
	if err != nil {
		t.Fatal(err)
	}

	otherToken, err := auth.Login(database.DB, admin.Username, oldPassword)
	if err != nil {
		t.Fatal(err)
	}

	handlers := &Handlers{db: database}

	router := gin.New()
	protected := router.Group("/api")
	protected.Use(handlers.RequireAdmin())
	protected.POST("/auth/change-password", handlers.ChangeAdminPassword)

	body, err := json.Marshal(gin.H{
		"current_password": oldPassword,
		"new_password":     newPassword,
	})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(
		http.MethodPost,
		"/api/auth/change-password",
		bytes.NewReader(body),
	)
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(&http.Cookie{
		Name:  sessionCookieName,
		Value: currentToken,
	})

	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf(
			"HTTP status = %d, want 200; body: %s",
			response.Code,
			response.Body.String(),
		)
	}

	if _, err := auth.ValidateSession(database.DB, currentToken); err != nil {
		t.Fatalf("current session invalidated: %v", err)
	}

	if _, err := auth.ValidateSession(database.DB, otherToken); err == nil {
		t.Fatal("other session was not revoked")
	}

	var reloaded db.AdminUser
	if err := database.DB.First(&reloaded, admin.ID).Error; err != nil {
		t.Fatal(err)
	}

	if !auth.VerifyPassword(newPassword, reloaded.PasswordHash) {
		t.Fatal("new password was not saved")
	}

	if auth.VerifyPassword(oldPassword, reloaded.PasswordHash) {
		t.Fatal("old password remains valid")
	}
}

func TestChangeAdminPasswordHTTPRejections(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		authorized bool
		wantStatus int
	}{
		{
			name:       "missing authentication",
			body:       `{"current_password":"CorrectPassword123!","new_password":"NewSecurePassword456!"}`,
			authorized: false,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "incorrect current password",
			body:       `{"current_password":"WrongPassword123!","new_password":"NewSecurePassword456!"}`,
			authorized: true,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "password reuse",
			body:       `{"current_password":"CorrectPassword123!","new_password":"CorrectPassword123!"}`,
			authorized: true,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "short password",
			body:       `{"current_password":"CorrectPassword123!","new_password":"short"}`,
			authorized: true,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "unexpected JSON field",
			body:       `{"current_password":"CorrectPassword123!","new_password":"NewSecurePassword456!","admin_id":999}`,
			authorized: true,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "oversized request",
			body:       `{"current_password":"CorrectPassword123!","new_password":"` + strings.Repeat("x", 5000) + `"}`,
			authorized: true,
			wantStatus: http.StatusRequestEntityTooLarge,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)

			database, err := db.NewDatabase(
				filepath.Join(t.TempDir(), "rejection-test.db"),
			)
			if err != nil {
				t.Fatal(err)
			}

			sqlDB, err := database.DB.DB()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = sqlDB.Close() })

			const originalPassword = "CorrectPassword123!"

			hash, err := auth.HashPassword(originalPassword)
			if err != nil {
				t.Fatal(err)
			}

			admin := db.AdminUser{
				Username:     "admin",
				PasswordHash: hash,
			}
			if err := database.DB.Create(&admin).Error; err != nil {
				t.Fatal(err)
			}

			token, err := auth.Login(
				database.DB,
				admin.Username,
				originalPassword,
			)
			if err != nil {
				t.Fatal(err)
			}

			handlers := &Handlers{db: database}

			router := gin.New()
			protected := router.Group("/api")
			protected.Use(handlers.RequireAdmin())
			protected.POST(
				"/auth/change-password",
				handlers.ChangeAdminPassword,
			)

			request := httptest.NewRequest(
				http.MethodPost,
				"/api/auth/change-password",
				strings.NewReader(tt.body),
			)
			request.Header.Set("Content-Type", "application/json")

			if tt.authorized {
				request.AddCookie(&http.Cookie{
					Name:  sessionCookieName,
					Value: token,
				})
			}

			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)

			if response.Code != tt.wantStatus {
				t.Fatalf(
					"status = %d, want %d; body: %s",
					response.Code,
					tt.wantStatus,
					response.Body.String(),
				)
			}

			var reloaded db.AdminUser
			if err := database.DB.
				First(&reloaded, admin.ID).Error; err != nil {
				t.Fatal(err)
			}

			if !auth.VerifyPassword(
				originalPassword,
				reloaded.PasswordHash,
			) {
				t.Fatal("rejected request modified the password")
			}

			if _, err := auth.ValidateSession(
				database.DB,
				token,
			); err != nil {
				t.Fatalf(
					"rejected request invalidated the session: %v",
					err,
				)
			}

			var auditCount int64
			if err := database.DB.
				Model(&db.AuditEvent{}).
				Where("action = ?", "admin.password_change").
				Count(&auditCount).Error; err != nil {
				t.Fatal(err)
			}

			if auditCount != 0 {
				t.Fatalf(
					"rejected request created %d password-change audit events",
					auditCount,
				)
			}
		})
	}
}

func TestChangeAdminPasswordAuthenticatedCSRF(t *testing.T) {
	gin.SetMode(gin.TestMode)

	database, err := db.NewDatabase(
		filepath.Join(t.TempDir(), "authenticated-csrf.db"),
	)
	if err != nil {
		t.Fatal(err)
	}

	sqlDB, err := database.DB.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	const oldPassword = "CorrectPassword123!"
	const newPassword = "NewSecurePassword456!"

	hash, err := auth.HashPassword(oldPassword)
	if err != nil {
		t.Fatal(err)
	}

	admin := db.AdminUser{
		Username:     "admin",
		PasswordHash: hash,
	}
	if err := database.DB.Create(&admin).Error; err != nil {
		t.Fatal(err)
	}

	currentToken, err := auth.Login(
		database.DB, admin.Username, oldPassword,
	)
	if err != nil {
		t.Fatal(err)
	}

	otherToken, err := auth.Login(
		database.DB, admin.Username, oldPassword,
	)
	if err != nil {
		t.Fatal(err)
	}

	handlers := &Handlers{db: database}
	router := gin.New()

	SetupRoutes(
		router,
		handlers,
		"https://step-ui.mjm.internal",
	)

	request := httptest.NewRequest(
		http.MethodPost,
		"/api/auth/change-password",
		strings.NewReader(
			`{"current_password":"CorrectPassword123!",`+
				`"new_password":"NewSecurePassword456!"}`,
		),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://attacker.example")
	request.AddCookie(&http.Cookie{
		Name:  sessionCookieName,
		Value: currentToken,
	})

	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf(
			"cross-origin request returned %d, want 403: %s",
			response.Code,
			response.Body.String(),
		)
	}

	var reloaded db.AdminUser
	if err := database.DB.First(&reloaded, admin.ID).Error; err != nil {
		t.Fatal(err)
	}

	if !auth.VerifyPassword(oldPassword, reloaded.PasswordHash) {
		t.Fatal("cross-origin request changed the password")
	}

	if auth.VerifyPassword(newPassword, reloaded.PasswordHash) {
		t.Fatal("new password was accepted despite CSRF rejection")
	}

	for name, token := range map[string]string{
		"current": currentToken,
		"other":   otherToken,
	} {
		if _, err := auth.ValidateSession(database.DB, token); err != nil {
			t.Fatalf("%s session was affected: %v", name, err)
		}
	}

	var auditCount int64
	if err := database.DB.
		Model(&db.AuditEvent{}).
		Where("action = ?", "admin.password_change").
		Count(&auditCount).Error; err != nil {
		t.Fatal(err)
	}

	if auditCount != 0 {
		t.Fatalf(
			"cross-origin request created %d audit events",
			auditCount,
		)
	}
}
