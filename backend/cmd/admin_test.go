package main

import (
	"path/filepath"
	"testing"
	"time"

	"step-ca-webui/internal/auth"
	"step-ca-webui/internal/db"
)

func TestResetAdminPasswordDatabaseTransaction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth-test.db")

	database, err := db.NewDatabase(path)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}

	sqlDB, err := database.DB.DB()
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()

	originalHash, err := auth.HashPassword("OriginalTestPassword123!")
	if err != nil {
		t.Fatal(err)
	}

	admin := db.AdminUser{
		Username:     "testadmin",
		PasswordHash: originalHash,
	}

	if err := database.DB.Create(&admin).Error; err != nil {
		t.Fatal(err)
	}

	session := db.AdminSession{
		AdminID:   admin.ID,
		TokenHash: "test-session-hash",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	if err := database.DB.Create(&session).Error; err != nil {
		t.Fatal(err)
	}

	newHash, err := auth.HashPassword("ReplacementTestPassword456!")
	if err != nil {
		t.Fatal(err)
	}

	// Exercise the actual password-reset implementation.
	err = updateAdminPassword(database.DB, admin.ID, newHash)

	if err != nil {
		t.Fatalf("password reset transaction failed: %v", err)
	}

	var updated db.AdminUser
	if err := database.DB.First(&updated, admin.ID).Error; err != nil {
		t.Fatal(err)
	}

	if !auth.VerifyPassword("ReplacementTestPassword456!", updated.PasswordHash) {
		t.Fatal("new password does not verify")
	}

	if auth.VerifyPassword("OriginalTestPassword123!", updated.PasswordHash) {
		t.Fatal("old password still verifies")
	}

	var sessions int64
	if err := database.DB.Model(&db.AdminSession{}).
		Where("admin_id = ?", admin.ID).
		Count(&sessions).Error; err != nil {
		t.Fatal(err)
	}

	if sessions != 0 {
		t.Fatalf("expected zero sessions after reset, got %d", sessions)
	}
}
