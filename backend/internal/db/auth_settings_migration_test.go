package db

import (
	"path/filepath"
	"testing"
)

func TestAuthSettingsMigration(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "migration-test.db")

	// Initialize a fresh database.
	first, err := NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("initial migration failed: %v", err)
	}

	// Verify that the authentication settings table exists.
	if !first.DB.Migrator().HasTable(&AuthSettings{}) {
		t.Fatal("auth_settings table was not created")
	}

	// Existing authentication tables must remain available.
	if !first.DB.Migrator().HasTable(&AdminUser{}) {
		t.Fatal("admin_users table is missing")
	}

	if !first.DB.Migrator().HasTable(&AdminSession{}) {
		t.Fatal("admin_sessions table is missing")
	}

	// Insert a representative administrator record.
	admin := AdminUser{
		Username:     "migration-test-admin",
		PasswordHash: "test-hash-not-a-real-password",
	}

	if err := first.DB.Create(&admin).Error; err != nil {
		t.Fatalf("create administrator: %v", err)
	}

	// Persist custom settings to verify migration does not overwrite them.
	settings := DefaultAuthSettings()
	settings.SessionDurationHours = 24

	if err := first.DB.Create(&settings).Error; err != nil {
		t.Fatalf("create authentication settings: %v", err)
	}

	// Close the first connection before reopening.
	sqlDB, err := first.DB.DB()
	if err != nil {
		t.Fatalf("get database connection: %v", err)
	}

	if err := sqlDB.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}

	// Reinitialize the same database.
	second, err := NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("repeat migration failed: %v", err)
	}

	secondSQLDB, err := second.DB.DB()
	if err != nil {
		t.Fatalf("get reopened database connection: %v", err)
	}
	defer secondSQLDB.Close()

	// Verify administrator data survived.
	var recoveredAdmin AdminUser

	if err := second.DB.First(
		&recoveredAdmin,
		"username = ?",
		admin.Username,
	).Error; err != nil {
		t.Fatalf("administrator lost after migration: %v", err)
	}

	// Verify authentication settings survived unchanged.
	var recoveredSettings AuthSettings

	if err := second.DB.First(&recoveredSettings).Error; err != nil {
		t.Fatalf("authentication settings lost: %v", err)
	}

	if recoveredSettings.SessionDurationHours != 24 {
		t.Fatalf(
			"session duration changed: got %d, want 24",
			recoveredSettings.SessionDurationHours,
		)
	}

	if !recoveredSettings.Validate() {
		t.Fatal("recovered authentication settings are invalid")
	}
}
