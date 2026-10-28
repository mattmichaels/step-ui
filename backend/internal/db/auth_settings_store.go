package db

import (
	"errors"
	"fmt"

	"gorm.io/gorm"
)

const authSettingsRowID uint = 1

// GetAuthSettings retrieves the application's authentication configuration.
// A fresh installation receives secure defaults without modifying the database.
func (d *Database) GetAuthSettings() (*AuthSettings, error) {
	var settings AuthSettings

	err := d.DB.First(&settings, authSettingsRowID).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		defaults := DefaultAuthSettings()
		return &defaults, nil
	}

	if err != nil {
		return nil, fmt.Errorf("load authentication settings: %w", err)
	}

	if !settings.Validate() {
		return nil, errors.New("stored authentication settings are invalid")
	}

	return &settings, nil
}

// SaveAuthSettings validates and persists the singleton configuration.
// The fixed primary key prevents multiple settings rows from being created.
func (d *Database) SaveAuthSettings(settings *AuthSettings) error {
	if settings == nil {
		return errors.New("authentication settings cannot be nil")
	}

	if !settings.Validate() {
		return errors.New("invalid authentication settings")
	}

	return d.DB.Transaction(func(tx *gorm.DB) error {
		return SaveAuthSettingsTx(tx, settings)
	})
}

// SaveAuthSettingsTx persists validated authentication settings using the
// caller's transaction, allowing settings changes and audit events to commit
// or roll back together.
func SaveAuthSettingsTx(tx *gorm.DB, settings *AuthSettings) error {
	if tx == nil {
		return errors.New("database transaction cannot be nil")
	}

	if settings == nil || !settings.Validate() {
		return errors.New("invalid authentication settings")
	}

	{
		var existing AuthSettings

		err := tx.First(&existing, authSettingsRowID).Error

		if errors.Is(err, gorm.ErrRecordNotFound) {
			newSettings := *settings
			newSettings.ID = authSettingsRowID

			return tx.Create(&newSettings).Error
		}

		if err != nil {
			return err
		}

		if !existing.Validate() {
			return errors.New("stored authentication settings are invalid")
		}

		return tx.Model(&existing).Updates(map[string]interface{}{
			"method":                 settings.Method,
			"requirement":            settings.Requirement,
			"session_duration_hours": settings.SessionDurationHours,
		}).Error
	}
}
