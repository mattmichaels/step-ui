package db

import "testing"

func TestDefaultAuthSettings(t *testing.T) {
	settings := DefaultAuthSettings()

	if settings.Method != AuthMethodForms {
		t.Errorf("unexpected authentication method: %q", settings.Method)
	}

	if settings.Requirement != AuthRequirementAlways {
		t.Errorf("unexpected authentication requirement: %q", settings.Requirement)
	}

	if settings.SessionDurationHours != 12 {
		t.Errorf("unexpected session duration: %d", settings.SessionDurationHours)
	}

	if !settings.Validate() {
		t.Fatal("default authentication settings must be valid")
	}
}

func TestAuthSettingsValidation(t *testing.T) {
	tests := []struct {
		name   string
		modify func(*AuthSettings)
		valid  bool
	}{
		{
			name:  "secure defaults",
			valid: true,
		},
		{
			name: "unsupported authentication method",
			modify: func(s *AuthSettings) {
				s.Method = "none"
			},
		},
		{
			name: "local authentication bypass rejected",
			modify: func(s *AuthSettings) {
				s.Requirement = "except_local"
			},
		},
		{
			name: "zero session duration rejected",
			modify: func(s *AuthSettings) {
				s.SessionDurationHours = 0
			},
		},
		{
			name: "excessive session duration rejected",
			modify: func(s *AuthSettings) {
				s.SessionDurationHours = 169
			},
		},
		{
			name: "minimum session duration",
			modify: func(s *AuthSettings) {
				s.SessionDurationHours = 1
			},
			valid: true,
		},
		{
			name: "maximum session duration",
			modify: func(s *AuthSettings) {
				s.SessionDurationHours = 168
			},
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings := DefaultAuthSettings()

			if tt.modify != nil {
				tt.modify(&settings)
			}

			if got := settings.Validate(); got != tt.valid {
				t.Errorf(
					"Validate() = %v, want %v",
					got,
					tt.valid,
				)
			}
		})
	}
}
