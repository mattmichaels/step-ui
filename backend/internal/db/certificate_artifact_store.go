package db

// 2026-11-12: REV01 - Add validated public-certificate artifact persistence.
// Reject private keys, unexpected PEM blocks, and malformed certificates.
// No private-key or PKCS#12 material is stored.
//
// 2026-11-12: REV02 - Enforce strict PEM block boundaries.
// Reject unexpected text before, between, or after certificates.
// Preserve existing persistence methods and validation behavior.

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm"
)

var ErrInvalidCertificatePEM = errors.New("invalid public certificate PEM")

func validatePublicCertificatePEM(value string, allowEmpty bool) error {
	if strings.TrimSpace(value) == "" {
		if allowEmpty && value == "" {
			return nil
		}
		return ErrInvalidCertificatePEM
	}

	remaining := []byte(value)
	count := 0

	for len(remaining) > 0 {
		// Whitespace is permitted between PEM blocks.
		remaining = bytes.TrimSpace(remaining)

		if len(remaining) == 0 {
			break
		}

		// pem.Decode searches forward for BEGIN markers.
		// Require the marker at the current position instead.
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return fmt.Errorf(
				"%w: unexpected content outside certificate PEM block",
				ErrInvalidCertificatePEM,
			)
		}

		block, rest := pem.Decode(remaining)
		if block == nil {
			return ErrInvalidCertificatePEM
		}

		if block.Type != "CERTIFICATE" {
			return fmt.Errorf(
				"%w: unexpected PEM block %q",
				ErrInvalidCertificatePEM,
				block.Type,
			)
		}

		if len(block.Headers) != 0 {
			return fmt.Errorf(
				"%w: PEM headers are not permitted",
				ErrInvalidCertificatePEM,
			)
		}

		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidCertificatePEM, err)
		}

		count++
		remaining = rest
	}

	if count == 0 {
		return ErrInvalidCertificatePEM
	}

	return nil
}

// SaveCertificateArtifact stores only validated public certificate material.
// The referenced certificate must already exist in the inventory.
func (d *Database) SaveCertificateArtifact(artifact *CertificateArtifact) error {
	if artifact == nil || artifact.CertificateID == "" {
		return errors.New("certificate artifact requires a certificate ID")
	}

	if err := validatePublicCertificatePEM(artifact.CertPEM, false); err != nil {
		return fmt.Errorf("certificate: %w", err)
	}

	if err := validatePublicCertificatePEM(artifact.ChainPEM, true); err != nil {
		return fmt.Errorf("chain: %w", err)
	}

	return d.DB.Transaction(func(tx *gorm.DB) error {
		var count int64

		if err := tx.Model(&Certificate{}).
			Where("id = ?", artifact.CertificateID).
			Count(&count).Error; err != nil {
			return err
		}

		if count != 1 {
			return gorm.ErrRecordNotFound
		}

		return tx.Create(artifact).Error
	})
}

// GetCertificateArtifact retrieves retained public certificate material.
func (d *Database) GetCertificateArtifact(id string) (*CertificateArtifact, error) {
	var artifact CertificateArtifact

	err := d.DB.
		Where("certificate_id = ?", id).
		First(&artifact).Error

	if err != nil {
		return nil, err
	}

	return &artifact, nil
}

// DeleteCertificateArtifact removes retained public certificate material.
func (d *Database) DeleteCertificateArtifact(id string) error {
	return d.DB.
		Where("certificate_id = ?", id).
		Delete(&CertificateArtifact{}).Error
}
