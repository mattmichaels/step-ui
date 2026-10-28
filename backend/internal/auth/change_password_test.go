package auth

import (
	"errors"
	"testing"

	"step-ca-webui/internal/db"
)

func TestChangePasswordPreservesCurrentSession(t *testing.T) {
	database, admin := setupLoginTest(t)

	const oldPassword = "CorrectPassword123!"
	const newPassword = "NewSecurePassword456!"

	// Create two independently authenticated sessions.
	currentToken, err := Login(
		database.DB,
		admin.Username,
		oldPassword,
	)
	if err != nil {
		t.Fatal(err)
	}

	otherToken, err := Login(
		database.DB,
		admin.Username,
		oldPassword,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Change the password using the current session.
	if err := ChangePassword(
		database.DB,
		admin.ID,
		currentToken,
		oldPassword,
		newPassword,
	); err != nil {
		t.Fatalf("password change failed: %v", err)
	}

	// The original password must no longer authenticate.
	if _, err := Login(
		database.DB,
		admin.Username,
		oldPassword,
	); err == nil {
		t.Fatal("old password still authenticates")
	}

	// The new password must authenticate.
	if _, err := Login(
		database.DB,
		admin.Username,
		newPassword,
	); err != nil {
		t.Fatalf("new password rejected: %v", err)
	}

	// The current session must remain valid.
	if _, err := ValidateSession(
		database.DB,
		currentToken,
	); err != nil {
		t.Fatalf("current session was revoked: %v", err)
	}

	// Other sessions must be invalidated.
	if _, err := ValidateSession(
		database.DB,
		otherToken,
	); err == nil {
		t.Fatal("other session remained valid")
	}

	// The change must be recorded in the audit log.
	var audit db.AuditEvent

	if err := database.DB.
		Where("action = ?", "admin.password_change").
		First(&audit).Error; err != nil {
		t.Fatalf("password-change audit event missing: %v", err)
	}

	if audit.Who != admin.Username {
		t.Fatalf(
			"audit actor = %q, want %q",
			audit.Who,
			admin.Username,
		)
	}
}

func TestChangePasswordRejectsInvalidRequests(t *testing.T) {
	cases := []struct {
		name            string
		currentPassword string
		newPassword     string
		invalidToken    bool
		wantError       error
	}{
		{
			name:            "incorrect current password",
			currentPassword: "DefinitelyWrong123!",
			newPassword:     "NewSecurePassword456!",
			wantError:       ErrIncorrectCurrentPassword,
		},
		{
			name:            "password reuse",
			currentPassword: "CorrectPassword123!",
			newPassword:     "CorrectPassword123!",
			wantError:       ErrPasswordReuse,
		},
		{
			name:            "password too short",
			currentPassword: "CorrectPassword123!",
			newPassword:     "Short123!",
			wantError:       ErrPasswordTooShort,
		},
		{
			name:            "invalid session token",
			currentPassword: "CorrectPassword123!",
			newPassword:     "NewSecurePassword456!",
			invalidToken:    true,
			wantError:       ErrInvalidSession,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			database, admin := setupLoginTest(t)

			token, err := Login(
				database.DB,
				admin.Username,
				"CorrectPassword123!",
			)
			if err != nil {
				t.Fatal(err)
			}

			if tc.invalidToken {
				token = "invalid-session-token"
			}

			err = ChangePassword(
				database.DB,
				admin.ID,
				token,
				tc.currentPassword,
				tc.newPassword,
			)

			if !errors.Is(err, tc.wantError) {
				t.Fatalf(
					"ChangePassword error = %v, want %v",
					err,
					tc.wantError,
				)
			}

			var reloaded db.AdminUser
			if err := database.DB.First(&reloaded, admin.ID).Error; err != nil {
				t.Fatal(err)
			}

			if !VerifyPassword("CorrectPassword123!", reloaded.PasswordHash) {
				t.Fatal("rejected request modified administrator password")
			}

			var sessionCount int64
			if err := database.DB.Model(&db.AdminSession{}).
				Where("admin_id = ?", admin.ID).
				Count(&sessionCount).Error; err != nil {
				t.Fatal(err)
			}

			if sessionCount != 1 {
				t.Fatalf(
					"rejected request changed session count to %d",
					sessionCount,
				)
			}

			var auditCount int64
			if err := database.DB.Model(&db.AuditEvent{}).
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

func TestChangePasswordRollsBackOnAuditFailure(t *testing.T) {
	database, admin := setupLoginTest(t)

	const oldPassword = "CorrectPassword123!"
	const newPassword = "NewSecurePassword456!"

	currentToken, err := Login(
		database.DB,
		admin.Username,
		oldPassword,
	)
	if err != nil {
		t.Fatal(err)
	}

	otherToken, err := Login(
		database.DB,
		admin.Username,
		oldPassword,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Force only password-change audit inserts to fail.
	// Existing login audit events remain unaffected.
	if err := database.DB.Exec(`
		CREATE TRIGGER reject_password_change_audit
		BEFORE INSERT ON audit_events
		WHEN NEW.action = 'admin.password_change'
		BEGIN
			SELECT RAISE(ABORT, 'simulated audit failure');
		END;
	`).Error; err != nil {
		t.Fatal(err)
	}

	err = ChangePassword(
		database.DB,
		admin.ID,
		currentToken,
		oldPassword,
		newPassword,
	)

	if err == nil {
		t.Fatal("password change succeeded despite audit failure")
	}

	// Password must remain unchanged.
	var reloaded db.AdminUser

	if err := database.DB.
		First(&reloaded, admin.ID).Error; err != nil {
		t.Fatal(err)
	}

	if !VerifyPassword(oldPassword, reloaded.PasswordHash) {
		t.Fatal("password update was not rolled back")
	}

	if VerifyPassword(newPassword, reloaded.PasswordHash) {
		t.Fatal("new password was committed despite audit failure")
	}

	// Both existing sessions must remain valid.
	for name, token := range map[string]string{
		"current": currentToken,
		"other":   otherToken,
	} {
		if _, err := ValidateSession(database.DB, token); err != nil {
			t.Fatalf(
				"%s session was revoked despite rollback: %v",
				name,
				err,
			)
		}
	}

	// No password-change audit event may exist.
	var count int64

	if err := database.DB.
		Model(&db.AuditEvent{}).
		Where("action = ?", "admin.password_change").
		Count(&count).Error; err != nil {
		t.Fatal(err)
	}

	if count != 0 {
		t.Fatalf(
			"found %d password-change audit events after rollback",
			count,
		)
	}
}

func TestChangePasswordRejectsAnotherAdminsSession(t *testing.T) {
	database, alice := setupLoginTest(t)

	const alicePassword = "CorrectPassword123!"
	const bobPassword = "BobSecurePassword123!"
	const newPassword = "AliceNewPassword456!"

	bobHash, err := HashPassword(bobPassword)
	if err != nil {
		t.Fatal(err)
	}

	bob := db.AdminUser{
		Username:     "bob",
		PasswordHash: bobHash,
	}

	if err := database.DB.Create(&bob).Error; err != nil {
		t.Fatal(err)
	}

	aliceToken, err := Login(
		database.DB,
		alice.Username,
		alicePassword,
	)
	if err != nil {
		t.Fatal(err)
	}

	bobToken, err := Login(
		database.DB,
		bob.Username,
		bobPassword,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Alice attempts to change her password using Bob's session.
	err = ChangePassword(
		database.DB,
		alice.ID,
		bobToken,
		alicePassword,
		newPassword,
	)

	if !errors.Is(err, ErrInvalidSession) {
		t.Fatalf(
			"cross-admin session error = %v, want ErrInvalidSession",
			err,
		)
	}

	// Alice's credentials must remain unchanged.
	var reloadedAlice db.AdminUser

	if err := database.DB.First(&reloadedAlice, alice.ID).Error; err != nil {
		t.Fatal(err)
	}

	if !VerifyPassword(alicePassword, reloadedAlice.PasswordHash) {
		t.Fatal("cross-admin attempt modified Alice's password")
	}

	// Both administrators must retain their sessions.
	for name, token := range map[string]string{
		"alice": aliceToken,
		"bob":   bobToken,
	} {
		if _, err := ValidateSession(database.DB, token); err != nil {
			t.Fatalf("%s session was affected: %v", name, err)
		}
	}

	// No password-change audit event should be recorded.
	var auditCount int64

	if err := database.DB.Model(&db.AuditEvent{}).
		Where("action = ?", "admin.password_change").
		Count(&auditCount).Error; err != nil {
		t.Fatal(err)
	}

	if auditCount != 0 {
		t.Fatalf(
			"cross-admin attempt created %d password-change audit events",
			auditCount,
		)
	}
}
