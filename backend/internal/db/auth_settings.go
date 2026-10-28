package db

import "time"

const (
	AuthMethodForms       = "forms"
	AuthRequirementAlways = "always"

	DefaultSessionDurationHours = 12
	MinSessionDurationHours     = 1
	MaxSessionDurationHours     = 168
)

// AuthSettings contains the application's authentication configuration.
//
// The initial implementation supports only forms authentication with
// authentication always required. Additional modes must be explicitly
// implemented and security-tested before they can be enabled.
type AuthSettings struct {
	ID                   uint      `gorm:"primaryKey" json:"-"`
	Method               string    `gorm:"not null;default:forms" json:"method"`
	Requirement          string    `gorm:"not null;default:always" json:"requirement"`
	SessionDurationHours int       `gorm:"not null;default:12" json:"session_duration_hours"`
	CreatedAt            time.Time `json:"-"`
	UpdatedAt            time.Time `json:"-"`
}

// DefaultAuthSettings returns a secure configuration for new installations.
func DefaultAuthSettings() AuthSettings {
	return AuthSettings{
		Method:               AuthMethodForms,
		Requirement:          AuthRequirementAlways,
		SessionDurationHours: DefaultSessionDurationHours,
	}
}

// Validate rejects unsupported authentication modes and session durations.
// Unknown values must never silently disable authentication.
func (s AuthSettings) Validate() bool {
	return s.Method == AuthMethodForms &&
		s.Requirement == AuthRequirementAlways &&
		s.SessionDurationHours >= MinSessionDurationHours &&
		s.SessionDurationHours <= MaxSessionDurationHours
}
