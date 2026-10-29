'use client'

import { useState, type FormEvent } from 'react'
import axios from 'axios'
import { useAuth } from '@/contexts/AuthContext'

export function LoginScreen() {
  const { login } = useAuth()

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()

    if (submitting) return

    setSubmitting(true)
    setError(null)

    try {
      await login(username.trim(), password)
    } catch (err) {
      if (axios.isAxiosError(err)) {
        switch (err.response?.status) {
          case 401:
            setError('Invalid username or password.')
            break
          case 429:
            setError('Too many login attempts. Please wait before trying again.')
            break
          default:
            setError('Unable to sign in. Please try again.')
        }
      } else {
        setError('Unable to sign in. Please try again.')
      }
    } finally {
      setSubmitting(false)
    }
  }

  const [showRecovery, setShowRecovery] = useState(false)

  const recoveryCommand =
    'docker compose exec backend ./main admin reset-password'

  const releaseRecoveryCommand =
    'docker compose -f docker-compose.yml -f docker-compose.auth-release.yml exec backend ./main admin reset-password'

  const [copiedCommand, setCopiedCommand] = useState<string | null>(null)

  const copyRecoveryCommand = async (command: string) => {
    try {
      await navigator.clipboard.writeText(command)
      setCopiedCommand(command)
      window.setTimeout(() => setCopiedCommand(null), 2000)
    } catch {
      setCopiedCommand(null)
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-slate-950 px-4">
      <div className="w-full max-w-md rounded-xl border border-slate-800 bg-slate-900 p-8 shadow-2xl">
        <div className="mb-8 text-center">
          <div className="mb-2 text-xs font-semibold uppercase tracking-[0.3em] text-sky-400">
            Certificate Authority
          </div>

          <h1 className="text-3xl font-bold text-white">
            Step UI
          </h1>

          <p className="mt-3 text-sm text-slate-400">
            Administrator sign in
          </p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <label
              htmlFor="username"
              className="mb-2 block text-sm font-medium text-slate-200"
            >
              Username
            </label>

            <input
              id="username"
              name="username"
              type="text"
              autoComplete="username"
              autoCapitalize="none"
              spellCheck={false}
              required
              maxLength={128}
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              disabled={submitting}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 text-white outline-none transition focus:border-sky-500 focus:ring-2 focus:ring-sky-500/20 disabled:opacity-50"
            />
          </div>

          <div>
            <label
              htmlFor="password"
              className="mb-2 block text-sm font-medium text-slate-200"
            >
              Password
            </label>

            <input
              id="password"
              name="password"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              disabled={submitting}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 text-white outline-none transition focus:border-sky-500 focus:ring-2 focus:ring-sky-500/20 disabled:opacity-50"
            />
          </div>

          {error && (
            <div
              role="alert"
              className="rounded-lg border border-red-900 bg-red-950/50 px-4 py-3 text-sm text-red-300"
            >
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={submitting}
            className="w-full rounded-lg bg-sky-600 px-4 py-3 font-semibold text-white transition hover:bg-sky-500 focus:outline-none focus:ring-2 focus:ring-sky-400 focus:ring-offset-2 focus:ring-offset-slate-900 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {submitting ? 'Signing in…' : 'Sign in'}
          </button>
        </form>

        <div className="mt-5 text-center">
          <button
            type="button"
            onClick={() => setShowRecovery(!showRecovery)}
            aria-expanded={showRecovery}
            aria-controls="password-recovery-panel"
            className="text-sm text-sky-400 transition hover:text-sky-300 hover:underline focus:outline-none focus:ring-2 focus:ring-sky-400"
          >
            Forgot password?
          </button>
        </div>

        {showRecovery && (
          <div
            id="password-recovery-panel"
            className="mt-5 rounded-lg border border-slate-700 bg-slate-950 p-4 text-left"
          >
            <h2 className="text-sm font-semibold text-white">
              Administrator Password Recovery
            </h2>

            <p className="mt-3 text-sm leading-relaxed text-slate-400">
              Password recovery requires authorized access to the
              Step UI server. From the directory containing your
              Docker Compose files, run:
            </p>

            <div className="mt-4 flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-900 p-2">
              <code className="min-w-0 flex-1 overflow-x-auto px-2 text-xs text-sky-300">
                {recoveryCommand}
              </code>

              <button
                type="button"
                onClick={() => copyRecoveryCommand(recoveryCommand)}
                className="shrink-0 rounded-md bg-slate-700 px-3 py-2 text-xs font-medium text-white transition hover:bg-slate-600 focus:outline-none focus:ring-2 focus:ring-sky-400"
                aria-label="Copy password recovery command"
              >
                {copiedCommand === recoveryCommand ? 'Copied!' : 'Copy'}
              </button>
            </div>

            <p className="mt-4 text-xs font-medium text-slate-300">
              Using the authentication-release Compose override?
            </p>

            <div className="mt-2 flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-900 p-2">
              <code className="min-w-0 flex-1 overflow-x-auto px-2 text-xs text-sky-300">
                {releaseRecoveryCommand}
              </code>

              <button
                type="button"
                onClick={() => copyRecoveryCommand(releaseRecoveryCommand)}
                className="shrink-0 rounded-md bg-slate-700 px-3 py-2 text-xs font-medium text-white transition hover:bg-slate-600 focus:outline-none focus:ring-2 focus:ring-sky-400"
                aria-label="Copy authentication-release recovery command"
              >
                {copiedCommand === releaseRecoveryCommand ? 'Copied!' : 'Copy'}
              </button>
            </div>

            <p className="mt-3 text-xs leading-relaxed text-slate-400">
              The command prompts for a new password and
              confirmation. Passwords must contain at least
              12 characters.
            </p>

            <p className="mt-3 text-xs leading-relaxed text-amber-300">
              Recovery invalidates all existing administrator
              sessions. CLI recovery currently requires exactly
              one configured administrator.
            </p>

            <p className="mt-3 text-xs text-slate-500">
              If you do not have server access, contact your
              system administrator.
            </p>
          </div>
        )}

        <p className="mt-8 text-center text-xs text-slate-500">
          Authorized administrators only
        </p>
      </div>
    </main>
  )
}
