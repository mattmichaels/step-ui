'use client'

import { FormEvent, useState } from 'react'
import axios from 'axios'
import { certificateApi } from '@/lib/api'

export default function ChangePassword() {
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()

    if (submitting) return

    setError('')
    setSuccess('')

    if (!currentPassword || !newPassword || !confirmPassword) {
      setError('All password fields are required.')
      return
    }

    if (newPassword.length < 12) {
      setError('New password must contain at least 12 characters.')
      return
    }

    if (newPassword === currentPassword) {
      setError('New password must differ from your current password.')
      return
    }

    if (newPassword !== confirmPassword) {
      setError('New password and confirmation do not match.')
      return
    }

    setSubmitting(true)

    try {
      await certificateApi.changePassword({
        current_password: currentPassword,
        new_password: newPassword,
      })

      setCurrentPassword('')
      setNewPassword('')
      setConfirmPassword('')

      setSuccess(
        'Password changed successfully. Other active sessions have been signed out.'
      )
    } catch (err: unknown) {
      if (axios.isAxiosError(err)) {
        const message = err.response?.data?.error

        setError(
          typeof message === 'string'
            ? message
            : 'Unable to change password. Please try again.'
        )
      } else {
        setError('Unable to change password. Please try again.')
      }
    } finally {
      setSubmitting(false)
    }
  }

  const inputClass =
    'w-full rounded-lg border border-gray-300 bg-white px-4 py-3 text-gray-900 outline-none transition focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 disabled:opacity-50'

  const labelClass = 'mb-2 block text-sm font-medium text-gray-700'

  return (
    <section className="rounded-lg bg-white p-6 shadow">
      <div className="mb-6">
        <h2 className="text-xl font-semibold text-gray-900">
          Change Password
        </h2>

        <p className="mt-2 text-sm text-gray-600">
          Update your administrator password. Your current session will
          remain active, but all other sessions will be signed out.
        </p>
      </div>

      <form onSubmit={handleSubmit} className="max-w-xl space-y-5">
        <div>
          <label htmlFor="current-password" className={labelClass}>
            Current Password
          </label>

          <input
            id="current-password"
            name="current-password"
            type="password"
            autoComplete="current-password"
            required
            value={currentPassword}
            onChange={(event) => {
              setCurrentPassword(event.target.value)
              setError('')
              setSuccess('')
            }}
            disabled={submitting}
            className={inputClass}
          />
        </div>

        <div>
          <label htmlFor="new-password" className={labelClass}>
            New Password
          </label>

          <input
            id="new-password"
            name="new-password"
            type="password"
            autoComplete="new-password"
            minLength={12}
            required
            value={newPassword}
            onChange={(event) => {
              setNewPassword(event.target.value)
              setError('')
              setSuccess('')
            }}
            disabled={submitting}
            className={inputClass}
          />

          <p className="mt-2 text-xs text-gray-500">
            Minimum 12 characters.
          </p>
        </div>

        <div>
          <label htmlFor="confirm-password" className={labelClass}>
            Confirm New Password
          </label>

          <input
            id="confirm-password"
            name="confirm-password"
            type="password"
            autoComplete="new-password"
            minLength={12}
            required
            value={confirmPassword}
            onChange={(event) => {
              setConfirmPassword(event.target.value)
              setError('')
              setSuccess('')
            }}
            disabled={submitting}
            className={inputClass}
          />
        </div>

        {error && (
          <div
            role="alert"
            className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700"
          >
            {error}
          </div>
        )}

        {success && (
          <div
            role="status"
            className="rounded-lg border border-green-200 bg-green-50 px-4 py-3 text-sm text-green-700"
          >
            {success}
          </div>
        )}

        <div className="flex justify-end">
          <button
            type="submit"
            disabled={submitting}
            className="rounded-lg bg-blue-600 px-5 py-2.5 font-medium text-white transition hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {submitting ? 'Changing Password...' : 'Change Password'}
          </button>
        </div>
      </form>
    </section>
  )
}
