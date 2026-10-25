// ── Unified Scan Orchestrator ──
// Runs all five analyzers (IaC, Crypto, SRI, Taint, BOLA) in parallel
// and merges results into a single findings array.

import { analyzeIaC } from './iac-analyzer.js'
import { analyzeCrypto } from './analyzers/crypto-analyzer.js'
import { checkSRI } from './sri-checker.js'
import { analyzeTaint } from './taint-tracker.js'
import { detectBOLA } from './bola-detector.js'

/**
 * Extension-to-analyzer routing table.
 */
const EXTENSION_MAP = {
  '.tf':   { analyzers: ['iac'], iacType: 'terraform' },
  '.yml':  { analyzers: ['iac'], iacType: 'cloudformation' },
  '.yaml': { analyzers: ['iac'], iacType: 'cloudformation' },
  '.js':   { analyzers: ['crypto', 'taint', 'bola'] },
  '.ts':   { analyzers: ['crypto', 'taint', 'bola'] },
  '.jsx':  { analyzers: ['crypto', 'taint', 'bola'] },
  '.tsx':  { analyzers: ['crypto', 'taint', 'bola'] },
  '.py':   { analyzers: ['crypto', 'taint'] },
  '.html': { analyzers: ['sri'] },
  '.htm':  { analyzers: ['sri'] },
  '.go':   { analyzers: ['crypto'] },
  '.java': { analyzers: ['crypto'] },
  '.rb':   { analyzers: ['crypto'] },
}

/**
 * Route files to applicable analyzers based on file extension.
 * @param {Array<{ path: string, content: string }>} files
 * @returns {Array<{ file: { path: string, content: string }, analyzers: string[], iacType?: string }>}
 */
export function routeFiles(files) {
  return files.map(file => {
    const dotIndex = file.path.lastIndexOf('.')
    const ext = dotIndex !== -1 ? file.path.slice(dotIndex).toLowerCase() : ''
    const mapping = EXTENSION_MAP[ext] || { analyzers: [] }
    return {
      file,
      analyzers: [...mapping.analyzers],
      ...(mapping.iacType ? { iacType: mapping.iacType } : {}),
    }
  })
}

/**
 * Run all applicable analyzers in parallel and merge results.
 * @param {Array<{ path: string, content: string }>} files
 * @returns {Promise<{ findings: object[], analyzerResults: object }>}
 */
export async function unifiedScan(files) {
  if (!files || files.length === 0) {
    return { findings: [], analyzerResults: {} }
  }

  const routed = routeFiles(files)

  // Group files by analyzer
  const groups = { iac: [], crypto: [], sri: [], taint: [], bola: [] }
  for (const entry of routed) {
    for (const analyzer of entry.analyzers) {
      if (groups[analyzer]) {
        groups[analyzer].push(entry)
      }
    }
  }

  // Build analyzer tasks
  const analyzerFns = {
    iac: () => {
      const results = []
      for (const entry of groups.iac) {
        results.push(...analyzeIaC(entry.file.content, entry.iacType, entry.file.path))
      }
      return results
    },
    crypto: () => {
      const results = []
      for (const entry of groups.crypto) {
        results.push(...analyzeCrypto(entry.file.content, entry.file.path))
      }
      return results
    },
    sri: () => {
      const results = []
      for (const entry of groups.sri) {
        results.push(...checkSRI(entry.file.content, entry.file.path))
      }
      return results
    },
    taint: () => {
      const results = []
      for (const entry of groups.taint) {
        results.push(...analyzeTaint(entry.file.content, entry.file.path))
      }
      return results
    },
    bola: () => {
      const results = []
      for (const entry of groups.bola) {
        results.push(...detectBOLA(entry.file.content, entry.file.path))
      }
      return results
    },
  }

  // Only run analyzers that have files routed to them
  const activeAnalyzers = Object.keys(groups).filter(k => groups[k].length > 0)
  const tasks = activeAnalyzers.map(name =>
    Promise.resolve().then(() => analyzerFns[name]()).then(findings => ({ name, findings }))
  )

  const settled = await Promise.allSettled(tasks)

  // Process results
  const allFindings = []
  const analyzerResults = {}

  for (const result of settled) {
    if (result.status === 'fulfilled') {
      const { name, findings } = result.value
      const tagged = findings.map(f => ({ ...f, analyzer: name }))
      allFindings.push(...tagged)
      analyzerResults[name] = { status: 'completed', count: findings.length }
    } else {
      // Extract analyzer name from the error context
      // Since Promise.allSettled preserves order, use index
      const idx = settled.indexOf(result)
      const name = activeAnalyzers[idx]
      analyzerResults[name] = { status: 'failed', error: result.reason?.message || 'Unknown error' }
    }
  }

  // Deduplicate by (file_path, line_number, category)
  const seen = new Set()
  const deduped = []
  for (const finding of allFindings) {
    const key = `${finding.file_path}:${finding.line_number}:${finding.category}`
    if (!seen.has(key)) {
      seen.add(key)
      deduped.push(finding)
    }
  }

  return { findings: deduped, analyzerResults }
}
