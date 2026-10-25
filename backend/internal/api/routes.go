package api

import (
	"github.com/gin-gonic/gin"
)

func SetupRoutes(r *gin.Engine, handlers *Handlers) {
	// Health check
	r.GET("/health", handlers.Health)

	// API routes
	api := r.Group("/api")
	{
		// Certificate operations
		api.POST("/certs/issue", handlers.IssueCertificate)
		api.POST("/certs/sign-csr", handlers.SignCSR)
		api.GET("/certs", handlers.ListCertificates)

		// 2026-10-24: Manual certificate archive and restore.
		api.GET("/certs/archived", handlers.ListArchivedCertificates)
		api.GET("/certs/:id", handlers.GetCertificate)
		api.POST("/certs/:id/renew", handlers.RenewCertificate)
		api.POST("/certs/:id/revoke", handlers.RevokeCertificate)
		api.POST("/certs/:id/archive", handlers.ArchiveCertificate)
		api.POST("/certs/:id/restore", handlers.RestoreCertificate)

		// Settings
		api.GET("/settings/ca", handlers.GetCASettings)
		api.PUT("/settings/ca", handlers.UpdateCASettings)
	}
}
