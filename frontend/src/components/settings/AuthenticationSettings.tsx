'use client'

import { useEffect, useState } from 'react'
import {
  certificateApi,
  type AuthenticationSettings as AuthenticationSettingsData,
} from '@/lib/api'

const SESSION_OPTIONS = [
  { hours: 1, label: '1 hour' },
  { hours: 6, label: '6 hours' },
  { hours: 12, label: '12 hours' },
  { hours: 24, label: '24 hours' },
  { hours: 48, label: '48 hours' },
  { hours: 72, label: '72 hours' },
  { hours: 168, label: '7 days' },
]

export default function AuthenticationSettings() {
  const [settings, setSettings] =
    useState<AuthenticationSettingsData | null>(null)

  const [savedSettings, setSavedSettings] =
    useState<AuthenticationSettingsData | null>(null)

  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  useEffect(() => {
    let active = true

    async function loadSettings() {
      try {
        const data = await certificateApi.getAuthenticationSettings()

        if (!active) return

        setSettings(data)
        setSavedSettings(data)
      } catch {
        if (active) {
          setError('Unable to load authentication settings.')
        }
      } finally {
        if (active) setLoading(false)
      }
    }

    loadSettings()

    return () => {
      active = false
    }
  }, [])

  const changed =
    settings !== null &&
    savedSettings !== null &&
    (
      settings.method !== savedSettings.method ||
      settings.requirement !== savedSettings.requirement ||
      settings.session_duration_hours !==
        savedSettings.session_duration_hours
    )

  async function saveSettings() {
    if (!settings || !changed || saving) return

    setSaving(true)
    setError('')
    setSuccess('')

    try {
      const updated =
        await certificateApi.updateAuthenticationSettings(settings)

      setSettings(updated)
      setSavedSettings(updated)
      setSuccess('Authentication settings saved successfully.')
    } catch {
      setError('Unable to save authentication settings.')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="bg-white rounded-lg shadow">
      <div className="px-6 py-4 border-b border-gray-200">
        <h2 className="text-lg font-medium text-gray-900">
          Authentication
        </h2>
        <p className="mt-1 text-sm text-gray-500">
          Configure administrator sign-in and session behavior.
        </p>
      </div>

      <div className="p-6 space-y-6">
        {loading ? (
          <p className="text-sm text-gray-500">
            Loading authentication settings...
          </p>
        ) : !settings ? (
          <div
            role="alert"
            className="rounded-md bg-red-50 p-4 text-sm text-red-700"
          >
            {error || 'Authentication settings are unavailable.'}
          </div>
        ) : (
          <>
            <div>
              <label
                htmlFor="auth-method"
                className="block text-sm font-medium text-gray-700"
              >
                Authentication Method
              </label>

              <select
                id="auth-method"
                value={settings.method}
                disabled
                className="mt-1 block w-full max-w-md rounded-md border border-gray-300 bg-gray-50 px-3 py-2 text-sm text-gray-900"
              >
                <option value="forms">Forms (Username / Password)</option>
              </select>

              <p className="mt-1 text-sm text-gray-500">
                Administrator credentials are required to sign in.
              </p>
            </div>

            <div>
              <label
                htmlFor="auth-requirement"
                className="block text-sm font-medium text-gray-700"
              >
                Authentication Requirement
              </label>

              <select
                id="auth-requirement"
                value={settings.requirement}
                disabled
                className="mt-1 block w-full max-w-md rounded-md border border-gray-300 bg-gray-50 px-3 py-2 text-sm text-gray-900"
              >
                <option value="always">Always</option>
              </select>

              <p className="mt-1 text-sm text-gray-500">
                Authentication is required for all administrative access.
              </p>
            </div>

            <div>
              <label
                htmlFor="session-duration"
                className="block text-sm font-medium text-gray-700"
              >
                Session Duration
              </label>

              <select
                id="session-duration"
                value={settings.session_duration_hours}
                disabled={saving}
                onChange={(event) => {
                  setSettings({
                    ...settings,
                    session_duration_hours: Number(event.target.value),
                  })
                  setSuccess('')
                }}
                className="mt-1 block w-full max-w-md rounded-md border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
              >
                {!SESSION_OPTIONS.some(
                  (option) =>
                    option.hours === settings.session_duration_hours
                ) && (
                  <option value={settings.session_duration_hours}>
                    {settings.session_duration_hours} hours
                  </option>
                )}

                {SESSION_OPTIONS.map((option) => (
                  <option key={option.hours} value={option.hours}>
                    {option.label}
                  </option>
                ))}
              </select>

              <p className="mt-1 text-sm text-gray-500">
                Changes affect new logins only. Existing sessions retain
                their original expiration.
              </p>
            </div>

            {error && (
              <div
                role="alert"
                className="rounded-md bg-red-50 p-4 text-sm text-red-700"
              >
                {error}
              </div>
            )}

            {success && (
              <div
                role="status"
                className="rounded-md bg-green-50 p-4 text-sm text-green-700"
              >
                {success}
              </div>
            )}

            <div className="flex items-center gap-4">
              <button
                type="button"
                onClick={saveSettings}
                disabled={!changed || saving}
                className="inline-flex items-center rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {saving ? 'Saving...' : 'Save Authentication Settings'}
              </button>

              {changed && !saving && (
                <span className="text-sm text-amber-700">
                  Unsaved changes
                </span>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  )
}
