package db

// 2026-11-13: REV01 - Add atomic certificate renewal metadata update
// and retained public-certificate artifact invalidation.
// Prevent historical downloads from serving a certificate whose
// serial number no longer matches the inventory record.
// Preserve existing UpdateCertificate behavior for revocation.

import (
	"errors"

	"gorm.io/gorm"
)

// UpdateCertificateAndInvalidateArtifact updates certificate metadata
// and removes any previously retained public certificate material.
//
// Both operations occur in one transaction. If either fails,
// neither change is committed.
//
// This method does not perform CA issuance or renewal.
func (d *Database) UpdateCertificateAndInvalidateArtifact(
	cert *Certificate,
) error {
	if cert == nil || cert.ID == "" {
		return errors.New("certificate requires a nonempty ID")
	}

	return d.DB.Transaction(func(tx *gorm.DB) error {
		result := tx.Model(&Certificate{}).
			Where("id = ?", cert.ID).
			Updates(map[string]interface{}{
				"serial":     cert.Serial,
				"not_after":  cert.NotAfter,
				"updated_at": cert.UpdatedAt,
			})

		if result.Error != nil {
			return result.Error
		}

		if result.RowsAffected != 1 {
			return gorm.ErrRecordNotFound
		}

		return tx.Where(
			"certificate_id = ?", cert.ID,
		).Delete(&CertificateArtifact{}).Error
	})
}
