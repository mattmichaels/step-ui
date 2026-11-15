// 2026-11-14: REV01 - Report retained public PEM availability without returning PEM bytes.
// Read-only aggregate for inventory, archive, and certificate details.
package db

// ArtifactAvailability exposes only whether public PEM material is retained.
type ArtifactAvailability struct {
	HasCertificate bool
	HasChain       bool
}

func (d *Database) GetArtifactAvailability() (map[string]ArtifactAvailability, error) {
	var rows []struct {
		CertificateID  string
		HasCertificate bool
		HasChain       bool
	}
	if err := d.DB.Model(&CertificateArtifact{}).
		Select("certificate_id, (length(cert_pem) > 0) AS has_certificate, (length(chain_pem) > 0) AS has_chain").Find(&rows).Error; err != nil {
		return nil, err
	}
	result := make(map[string]ArtifactAvailability, len(rows))
	for _, row := range rows {
		result[row.CertificateID] = ArtifactAvailability{
			HasCertificate: row.HasCertificate,
			HasChain:       row.HasChain,
		}
	}
	return result, nil
}
