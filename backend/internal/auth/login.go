package auth

import (
	"errors"
	"time"

	"gorm.io/gorm"

	"step-ca-webui/internal/db"
)

var ErrInvalidCredentials = errors.New("invalid username or password")

var dummyPasswordHash = func() string {
	hash, err := HashPassword("not-a-real-administrator-password")
	if err != nil {
		panic("failed to initialize authentication dummy hash")
	}
	return hash
}()

// Login verifies credentials and creates an audited session.
// Both session creation and its audit event are committed atomically.
func Login(database *gorm.DB, username, password string) (string, error) {
	return LoginWithDuration(database, username, password, SessionDuration)
}

// LoginWithDuration verifies credentials and creates an audited session
// using the requested session lifetime.
func LoginWithDuration(
	database *gorm.DB,
	username, password string,
	duration time.Duration,
) (string, error) {
	if duration < time.Duration(db.MinSessionDurationHours)*time.Hour ||
		duration > time.Duration(db.MaxSessionDurationHours)*time.Hour {
		return "", errors.New("invalid session duration")
	}

	var admin db.AdminUser

	err := database.
		Where("username = ?", username).
		First(&admin).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		// Perform an equivalent Argon2id verification for unknown users.
		// This reduces username-enumeration timing differences.
		VerifyPassword(password, dummyPasswordHash)
		return "", ErrInvalidCredentials
	}

	if err != nil {
		return "", err
	}

	if !VerifyPassword(password, admin.PasswordHash) {
		return "", ErrInvalidCredentials
	}

	var token string

	err = database.Transaction(func(tx *gorm.DB) error {
		var err error

		token, err = CreateSessionWithDuration(tx, admin.ID, duration)
		if err != nil {
			return err
		}

		return tx.Create(&db.AuditEvent{
			Who:       admin.Username,
			Action:    "admin.login",
			Details:   "Administrator authenticated successfully",
			Timestamp: time.Now().UTC(),
		}).Error
	})

	if err != nil {
		return "", err
	}

	return token, nil
}
