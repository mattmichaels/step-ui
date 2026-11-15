package db

import "time"

// 2026-11-12: REV01 - Introduce optional public-certificate retention.
// Store only public certificate and intermediate-chain PEM data.
// Private keys, PKCS#12 bundles, and passwords must never be persisted here.

// CertificateArtifact stores public certificate material for future downloads.
// The certificate ID corresponds to an existing Certificate inventory record.
type CertificateArtifact struct {
	CertificateID string    `gorm:"primaryKey;not null" json:"certificate_id"`
	CertPEM       string    `gorm:"type:text;not null" json:"-"`
	ChainPEM      string    `gorm:"type:text" json:"-"`
	CreatedAt     time.Time `json:"created_at"`
}
