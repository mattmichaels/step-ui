package db

import (
	"path/filepath"
	"testing"
)

func TestAuthSettingsStore(t *testing.T) {
	database, err := NewDatabase(filepath.Join(t.TempDir(), "auth-settings.db"))
	if err != nil {
		t.Fatalf("initialize database: %v", err)
	}

	sqlDB, err := database.DB.DB()
	if err != nil {
		t.Fatalf("get SQL connection: %v", err)
	}
	defer sqlDB.Close()

	t.Run("fresh database returns secure defaults", func(t *testing.T) {
		settings, err := database.GetAuthSettings()
		if err != nil {
			t.Fatalf("get defaults: %v", err)
		}

		if !settings.Validate() ||
			settings.Method != AuthMethodForms ||
			settings.Requirement != AuthRequirementAlways ||
			settings.SessionDurationHours != 12 {
			t.Fatalf("unexpected defaults: %+v", settings)
		}

		var count int64
		if err := database.DB.Model(&AuthSettings{}).Count(&count).Error; err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("reading defaults created %d rows", count)
		}
	})

	t.Run("save creates singleton", func(t *testing.T) {
		settings := DefaultAuthSettings()
		settings.SessionDurationHours = 24

		if err := database.SaveAuthSettings(&settings); err != nil {
			t.Fatalf("save settings: %v", err)
		}

		saved, err := database.GetAuthSettings()
		if err != nil {
			t.Fatal(err)
		}
		if saved.SessionDurationHours != 24 {
			t.Fatalf("duration = %d, want 24", saved.SessionDurationHours)
		}
	})

	t.Run("update preserves singleton", func(t *testing.T) {
		settings := DefaultAuthSettings()
		settings.SessionDurationHours = 48

		if err := database.SaveAuthSettings(&settings); err != nil {
			t.Fatal(err)
		}

		var count int64
		if err := database.DB.Model(&AuthSettings{}).Count(&count).Error; err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("settings rows = %d, want 1", count)
		}

		saved, err := database.GetAuthSettings()
		if err != nil {
			t.Fatal(err)
		}
		if saved.SessionDurationHours != 48 {
			t.Fatalf("duration = %d, want 48", saved.SessionDurationHours)
		}
	})

	t.Run("invalid settings do not overwrite saved values", func(t *testing.T) {
		invalid := DefaultAuthSettings()
		invalid.Method = "none"

		if err := database.SaveAuthSettings(&invalid); err == nil {
			t.Fatal("expected unsupported method to be rejected")
		}

		if err := database.SaveAuthSettings(nil); err == nil {
			t.Fatal("expected nil settings to be rejected")
		}

		saved, err := database.GetAuthSettings()
		if err != nil {
			t.Fatal(err)
		}
		if saved.SessionDurationHours != 48 {
			t.Fatal("invalid update changed saved settings")
		}
	})

	t.Run("corrupted stored settings fail closed", func(t *testing.T) {
		if err := database.DB.Model(&AuthSettings{}).
			Where("id = ?", 1).
			Update("requirement", "except_local").Error; err != nil {
			t.Fatal(err)
		}

		if _, err := database.GetAuthSettings(); err == nil {
			t.Fatal("expected corrupted settings to be rejected")
		}

		valid := DefaultAuthSettings()
		if err := database.SaveAuthSettings(&valid); err == nil {
			t.Fatal("expected update of corrupted settings to be rejected")
		}
	})
}
