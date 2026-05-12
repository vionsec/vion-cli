import { execSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { platform } from 'node:os'

/**
 * Probe whether `bash` is reachable from the current machine. The agent's
 * slash-command markdown (Claude Code / Codex / Blackbox) issues `curl`
 * commands through bash; on Windows that means Git for Windows must be
 * installed, since CMD and PowerShell can't run those scripts.
 *
 * macOS/Linux always have bash natively, so we skip the probe there.
 *
 * On Windows we accept any of:
 *   1. `bash` resolvable through PATH (Git for Windows option
 *      "Git from the command line and also from 3rd-party software")
 *   2. `bash.exe` present at a known Git for Windows install path
 *      — covers the default "Use Git from Git Bash only" option, which
 *      doesn't put bash in the system PATH but still ships with it.
 */
const KNOWN_GIT_BASH_PATHS = [
  'C:\\Program Files\\Git\\bin\\bash.exe',
  'C:\\Program Files\\Git\\usr\\bin\\bash.exe',
  'C:\\Program Files (x86)\\Git\\bin\\bash.exe',
  'C:\\Program Files (x86)\\Git\\usr\\bin\\bash.exe',
]

export function bashAvailable() {
  if (platform() !== 'win32') return true

  try {
    execSync('bash --version', { stdio: 'ignore', timeout: 3000 })
    return true
  } catch {
    // PATH miss — try known install locations.
  }

  for (const p of KNOWN_GIT_BASH_PATHS) {
    if (existsSync(p)) return true
  }

  // Honor LOCALAPPDATA single-user installs of Git for Windows.
  const localAppData = process.env.LOCALAPPDATA
  if (localAppData) {
    const candidates = [
      `${localAppData}\\Programs\\Git\\bin\\bash.exe`,
      `${localAppData}\\Programs\\Git\\usr\\bin\\bash.exe`,
    ]
    for (const p of candidates) {
      if (existsSync(p)) return true
    }
  }

  return false
}

export function isWindows() {
  return platform() === 'win32'
}
