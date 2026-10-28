package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"step-ca-webui/internal/auth"
	"step-ca-webui/internal/db"
)

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// ChangeAdminPassword changes the authenticated administrator's password.
// The current session is preserved; all other sessions are revoked.
func (h *Handlers) ChangeAdminPassword(c *gin.Context) {
	adminValue, exists := c.Get(authenticatedAdminKey)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Authentication required",
		})
		return
	}

	admin, ok := adminValue.(*db.AdminUser)
	if !ok || admin == nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Authentication required",
		})
		return
	}

	cookie, err := c.Request.Cookie(sessionCookieName)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Authentication required",
		})
		return
	}

	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 4096)

	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()

	var request changePasswordRequest

	if err := decoder.Decode(&request); err != nil {
		writeChangePasswordDecodeError(c, err)
		return
	}

	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Unexpected JSON content",
			})
		} else {
			writeChangePasswordDecodeError(c, err)
		}
		return
	}

	if strings.TrimSpace(request.CurrentPassword) == "" ||
		strings.TrimSpace(request.NewPassword) == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Both password fields are required",
		})
		return
	}

	err = auth.ChangePassword(
		h.db.DB,
		admin.ID,
		cookie.Value,
		request.CurrentPassword,
		request.NewPassword,
	)

	switch {
	case err == nil:
		c.JSON(http.StatusOK, gin.H{
			"message": "Password changed successfully",
		})

	case errors.Is(err, auth.ErrIncorrectCurrentPassword):
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Current password is incorrect",
		})

	case errors.Is(err, auth.ErrPasswordReuse):
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "New password must differ from current password",
		})

	case errors.Is(err, auth.ErrPasswordTooShort):
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "New password must contain at least 12 characters",
		})

	case errors.Is(err, auth.ErrInvalidSession):
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid or expired session",
		})

	default:
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Password change temporarily unavailable",
		})
	}
}

func writeChangePasswordDecodeError(c *gin.Context, err error) {
	var maxBytesError *http.MaxBytesError

	if errors.As(err, &maxBytesError) {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{
			"error": "Request body too large",
		})
		return
	}

	c.JSON(http.StatusBadRequest, gin.H{
		"error": "Invalid password-change request",
	})
}
