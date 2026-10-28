package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"step-ca-webui/internal/db"
)

type updateAuthSettingsRequest struct {
	Method               string `json:"method"`
	Requirement          string `json:"requirement"`
	SessionDurationHours int    `json:"session_duration_hours"`
}

// GetAuthSettings returns the current authentication configuration.
func (h *Handlers) GetAuthSettings(c *gin.Context) {
	settings, err := h.db.GetAuthSettings()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to load authentication settings",
		})
		return
	}

	c.JSON(http.StatusOK, settings)
}

// UpdateAuthSettings validates, saves, and audits configuration changes.
func (h *Handlers) UpdateAuthSettings(c *gin.Context) {
	admin, ok := CurrentAdmin(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Authentication required",
		})
		return
	}

	var request updateAuthSettingsRequest

	c.Request.Body = http.MaxBytesReader(
		c.Writer,
		c.Request.Body,
		4096,
	)

	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&request); err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{
				"error": "Authentication settings request exceeds 4096 bytes",
			})
			return
		}

		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid authentication settings request",
		})
		return
	}

	var extra interface{}
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{
				"error": "Authentication settings request exceeds 4096 bytes",
			})
			return
		}

		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Request must contain exactly one JSON object",
		})
		return
	}

	settings := db.AuthSettings{
		Method:               request.Method,
		Requirement:          request.Requirement,
		SessionDurationHours: request.SessionDurationHours,
	}

	if !settings.Validate() {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Unsupported authentication configuration",
		})
		return
	}

	err := h.db.DB.Transaction(func(tx *gorm.DB) error {
		if err := db.SaveAuthSettingsTx(tx, &settings); err != nil {
			return err
		}

		return tx.Create(&db.AuditEvent{
			Who:       admin.Username,
			Action:    "admin.auth_settings.update",
			Details:   "Administrator updated authentication settings",
			Timestamp: time.Now().UTC(),
		}).Error
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to save authentication settings",
		})
		return
	}

	c.JSON(http.StatusOK, settings)
}
