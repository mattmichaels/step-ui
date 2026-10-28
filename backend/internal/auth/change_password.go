package auth

import (
	"errors"
	"time"

	"gorm.io/gorm"

	"step-ca-webui/internal/db"
)

var (
	ErrIncorrectCurrentPassword = errors.New("incorrect current password")
	ErrPasswordReuse            = errors.New("new password must differ from current password")
	ErrPasswordTooShort         = errors.New("password must contain at least 12 characters")
)

// ChangePassword updates an administrator's password while preserving the
// authenticated session making the request.
//
// The password update, revocation of other sessions, and audit event are
// committed atomically.
func ChangePassword(
	database *gorm.DB,
	adminID uint,
	currentSessionToken string,
	currentPassword string,
	newPassword string,
) error {
	if len(newPassword) < 12 {
		return ErrPasswordTooShort
	}

	if currentPassword == newPassword {
		return ErrPasswordReuse
	}

	sessionHash, err := SessionTokenHash(currentSessionToken)
	if err != nil {
		return err
	}

	return database.Transaction(func(tx *gorm.DB) error {
		var session db.AdminSession

		if err := tx.
			Where(
				"admin_id = ? AND token_hash = ? AND expires_at > ?",
				adminID,
				sessionHash,
				time.Now().UTC(),
			).
			First(&session).Error; err != nil {
			return ErrInvalidSession
		}

		var admin db.AdminUser

		if err := tx.First(&admin, adminID).Error; err != nil {
			return ErrInvalidSession
		}

		if !VerifyPassword(currentPassword, admin.PasswordHash) {
			return ErrIncorrectCurrentPassword
		}

		if VerifyPassword(newPassword, admin.PasswordHash) {
			return ErrPasswordReuse
		}

		newHash, err := HashPassword(newPassword)
		if err != nil {
			return err
		}

		// Conditional update prevents overwriting a password that another
		// transaction changed after this administrator was loaded.
		result := tx.Model(&db.AdminUser{}).
			Where(
				"id = ? AND password_hash = ?",
				adminID,
				admin.PasswordHash,
			).
			Update("password_hash", newHash)

		if result.Error != nil {
			return result.Error
		}

		if result.RowsAffected != 1 {
			return errors.New("administrator credentials changed concurrently")
		}

		if err := tx.
			Where(
				"admin_id = ? AND token_hash <> ?",
				adminID,
				sessionHash,
			).
			Delete(&db.AdminSession{}).Error; err != nil {
			return err
		}

		return tx.Create(&db.AuditEvent{
			Who:       admin.Username,
			Action:    "admin.password_change",
			Details:   "Administrator changed password; other sessions invalidated",
			Timestamp: time.Now().UTC(),
		}).Error
	})
}
