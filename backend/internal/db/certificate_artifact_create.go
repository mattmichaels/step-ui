package db

// 2026-11-12: REV01 - Add transactional certificate inventory and
// optional public-certificate artifact creation.
// Validate public PEM before database writes.
// Never accept private-key or PKCS#12 material for retention.

import (
	"errors"
	"fmt"

	"gorm.io/gorm"
)

// CreateCertificateWithArtifact atomically creates certificate inventory
// metadata and, when provided, its retained public certificate material.
//
// A nil artifact preserves metadata-only creation behavior.
//
// The certificate authority issuance itself is outside this transaction.
func (d *Database) CreateCertificateWithArtifact(
	cert *Certificate,
	artifact *CertificateArtifact,
) error {
	if cert == nil || cert.ID == "" {
		return errors.New("certificate requires a nonempty ID")
	}

	if artifact != nil {
		if artifact.CertificateID != cert.ID {
			return errors.New("artifact certificate ID does not match inventory ID")
		}

		if err := validatePublicCertificatePEM(artifact.CertPEM, false); err != nil {
			return fmt.Errorf("certificate: %w", err)
		}

		if err := validatePublicCertificatePEM(artifact.ChainPEM, true); err != nil {
			return fmt.Errorf("chain: %w", err)
		}
	}

	return d.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(cert).Error; err != nil {
			return err
		}

		if artifact != nil {
			if err := tx.Create(artifact).Error; err != nil {
				return err
			}
		}

		return nil
	})
}
