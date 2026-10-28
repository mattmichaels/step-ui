import axios from 'axios'

const API_URL = '' // Same-origin API requests through Caddy

const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
})

export interface Certificate {
  id: string
  cn: string
  sans: string[]
  not_after: string
  status: string
  key_strategy: string
  key_type: string
  created_at: string
  updated_at: string
  serial: string
  archived_at: string | null
}

export interface IssueRequest {
  cn: string
  sans: string[]
  not_after_days: number
  key_type: 'rsa-2048' | 'ec-p256'
  format: 'pem' | 'pfx'
  pfx_password?: string
}

export interface SignCSRRequest {
  csr_pem: string
  not_after_days: number
}

export interface CertBundle {
  data: string
  filename: string
  mime_type: string
}

export interface CASettings {
  ca_url: string
  root_fingerprint: string
  acme_directories: string[]
  default_dns_suffix: string
  append_dns_suffix: boolean
}

export interface UpdateCASettingsRequest {
  default_dns_suffix: string
  append_dns_suffix: boolean
}

export interface AuthenticationSettings {
  method: 'forms'
  requirement: 'always'
  session_duration_hours: number
}

export type UpdateAuthenticationSettingsRequest = AuthenticationSettings

export interface ChangePasswordRequest {
  current_password: string
  new_password: string
}

export interface ChangePasswordResponse {
  message: string
}

export const certificateApi = {
  // Issue a new certificate
  issueCertificate: async (data: IssueRequest) => {
    const response = await api.post('/api/certs/issue', data)
    return response.data
  },

  // Sign a CSR
  signCSR: async (data: SignCSRRequest) => {
    const response = await api.post('/api/certs/sign-csr', data)
    return response.data
  },

  // List certificates
  listCertificates: async (params?: {
    limit?: number
    offset?: number
    status?: string
  }) => {
    const response = await api.get('/api/certs', { params })
    return response.data
  },

  // 2026-10-24: List manually archived certificates
  listArchivedCertificates: async (params?: {
    limit?: number
    offset?: number
  }) => {
    const response = await api.get('/api/certs/archived', { params })
    return response.data
  },

  // 2026-10-24: Archive an expired or revoked certificate
  archiveCertificate: async (id: string) => {
    const response = await api.post(`/api/certs/${id}/archive`)
    return response.data
  },

  // 2026-10-24: Restore an archived certificate to inventory
  restoreCertificate: async (id: string) => {
    const response = await api.post(`/api/certs/${id}/restore`)
    return response.data
  },

  // Get a specific certificate
  getCertificate: async (id: string) => {
    const response = await api.get(`/api/certs/${id}`)
    return response.data
  },

  // Renew a certificate
  renewCertificate: async (id: string) => {
    const response = await api.post(`/api/certs/${id}/renew`)
    return response.data
  },

  // Revoke a certificate
  revokeCertificate: async (id: string) => {
    const response = await api.post(`/api/certs/${id}/revoke`)
    return response.data
  },

  // Get CA settings
  getCASettings: async () => {
    const response = await api.get('/api/settings/ca')
    return response.data
  },

  // Update CA UI preferences
  updateCASettings: async (data: UpdateCASettingsRequest) => {
    const response = await api.put('/api/settings/ca', data)
    return response.data
  },

  // Get administrator authentication settings
  getAuthenticationSettings: async (): Promise<AuthenticationSettings> => {
    const response = await api.get<AuthenticationSettings>(
      '/api/settings/authentication'
    )
    return response.data
  },

  // Update administrator authentication settings
  updateAuthenticationSettings: async (
    data: UpdateAuthenticationSettingsRequest
  ): Promise<AuthenticationSettings> => {
    const response = await api.put<AuthenticationSettings>(
      '/api/settings/authentication',
      data
    )
    return response.data
  },

  // Change the authenticated administrator's password
  changePassword: async (
    data: ChangePasswordRequest
  ): Promise<ChangePasswordResponse> => {
    const response = await api.post<ChangePasswordResponse>(
      '/api/auth/change-password',
      data
    )
    return response.data
  },

  // Health check
  health: async () => {
    const response = await api.get('/health')
    return response.data
  },
}

export default api
