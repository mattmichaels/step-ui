// 2026-11-13: REV02 - Add historical intermediate-chain PEM download.
// Preserve the existing public leaf certificate download behavior.
// Return 404 when no retained intermediate chain is available.

// 2026-11-13: REV01 - Add historical public leaf certificate download.
// Retrieve only explicitly retained public certificate PEM.
// Distinguish missing records from unexpected database errors.
// Do not expose private keys, PKCS#12 bundles, or passwords.

package api

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// DownloadRetainedCertificate serves a previously retained public leaf certificate.
// Authentication is enforced by the route group when this handler is registered.
func (h *Handlers) DownloadRetainedCertificate(c *gin.Context) {
	certID := c.Param("id")

	if _, err := h.db.GetCertificate(certID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Certificate not found"})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve certificate"})
		return
	}

	artifact, err := h.db.GetCertificateArtifact(certID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Retained certificate not available"})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve retained certificate"})
		return
	}

	if artifact.CertPEM == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "Retained certificate not available"})
		return
	}

	c.Header("Content-Disposition", `attachment; filename="certificate.crt"`)
	c.Header("Cache-Control", "no-store")
	c.Data(http.StatusOK, "application/x-pem-file", []byte(artifact.CertPEM))
}

// DownloadRetainedCertificateChain serves a previously retained public
// intermediate certificate chain. Authentication is enforced by the route group.
func (h *Handlers) DownloadRetainedCertificateChain(c *gin.Context) {
	certID := c.Param("id")

	if _, err := h.db.GetCertificate(certID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Certificate not found"})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve certificate"})
		return
	}

	artifact, err := h.db.GetCertificateArtifact(certID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Retained certificate chain not available"})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve retained certificate chain"})
		return
	}

	if artifact.ChainPEM == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "Retained certificate chain not available"})
		return
	}

	c.Header("Content-Disposition", `attachment; filename="certificate-chain.pem"`)
	c.Header("Cache-Control", "no-store")
	c.Data(http.StatusOK, "application/x-pem-file", []byte(artifact.ChainPEM))
}
