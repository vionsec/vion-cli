/**
 * VION Database Detector — Server-side proprietary logic
 * Detects RLS issues, permissive policies, service role misuse, sensitive fields.
 */

/**
 * Detect database vulnerabilities
 * @param {Object} data - { files, sql_files, grep_results }
 * @returns {Array} findings
 */
export function detectDatabase(data) {
  const findings = []
  const files = data.files || {}
  const sqlFiles = data.sql_files || {}

  // Analyze SQL files
  for (const [filePath, content] of Object.entries(sqlFiles)) {
    const tables = [...content.matchAll(/CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)/gi)]

    for (const tableMatch of tables) {
      const tableName = tableMatch[1]
      const tableSection = content.substring(tableMatch.index, content.indexOf(';', tableMatch.index) + 1 || content.length)

      // Check RLS
      const hasRLS = new RegExp(`ALTER\\s+TABLE\\s+${tableName}\\s+ENABLE\\s+ROW\\s+LEVEL\\s+SECURITY`, 'i').test(content)
      if (!hasRLS) {
        findings.push({
          severity: 'critico',
          title: `Tabela '${tableName}' sem Row Level Security`,
          file: filePath,
          description: `A tabela ${tableName} nao tem RLS habilitado. Qualquer usuario autenticado pode acessar todos os registros.`,
          fix: `ALTER TABLE ${tableName} ENABLE ROW LEVEL SECURITY; CREATE POLICY "${tableName}_user_policy" ON ${tableName} FOR ALL USING (auth.uid() = user_id);`,
          category: 'Database',
        })
      }

      // Check for permissive policies
      const permissive = new RegExp(`POLICY[^;]*ON\\s+${tableName}[^;]*FOR\\s+ALL\\s+USING\\s*\\(\\s*true\\s*\\)`, 'gi')
      if (permissive.test(content)) {
        findings.push({
          severity: 'critico',
          title: `Politica RLS permissiva na tabela '${tableName}'`,
          file: filePath,
          description: `Politica com FOR ALL USING (true) equivale a nao ter RLS.`,
          fix: `Substituir USING (true) por USING (auth.uid() = user_id) ou condicao restritiva.`,
          category: 'Database',
        })
      }

      // Check sensitive fields without encryption
      const sensitiveFields = /(password|senha|credit_card|cartao|cpf|ssn|api_key)\s+(text|varchar|char)/gi
      const sensitiveMatches = [...tableSection.matchAll(sensitiveFields)]
      for (const sm of sensitiveMatches) {
        findings.push({
          severity: 'alto',
          title: `Campo sensivel '${sm[1]}' sem criptografia`,
          file: filePath,
          description: `O campo ${sm[1]} e armazenado como ${sm[2]} (texto plano). Dados sensiveis devem ser criptografados ou hasheados.`,
          fix: `Usar hash (bcrypt/argon2) para senhas, criptografia (pgcrypto) para dados sensiveis.`,
          category: 'Database',
        })
      }
    }
  }

  // Check source files for database issues
  for (const [filePath, content] of Object.entries(files)) {
    if (/(__tests__|\.test\.|node_modules)/i.test(filePath)) continue

    // Service role used in frontend
    if (/src\/|components\/|pages\/|views\//i.test(filePath)) {
      if (/service_role|service_key|supabase_admin/i.test(content)) {
        findings.push({
          severity: 'critico',
          title: 'Service role key usada no frontend',
          file: filePath,
          description: 'A service_role_key do Supabase ignora RLS. Nunca deve ser usada no frontend.',
          fix: 'Usar apenas a anon key no frontend. Service role deve ficar exclusivamente no backend.',
          category: 'Database',
        })
      }
    }

    // SELECT * without filter
    if (/\.from\s*\(\s*["'][^"']+["']\s*\)\s*\.select\s*\(\s*["']\*["']\s*\)(?![\s\S]{0,50}\.eq|\.filter|\.match)/i.test(content)) {
      const match = content.match(/\.from\s*\(\s*["']([^"']+)["']\s*\)\s*\.select\s*\(\s*["']\*["']\s*\)/)
      if (match) {
        findings.push({
          severity: 'medio',
          title: `SELECT * sem filtro na tabela '${match[1]}'`,
          file: filePath,
          description: 'Buscar todos os registros sem filtro pode expor dados de outros usuarios.',
          fix: 'Adicionar .eq("user_id", userId) ou filtro equivalente.',
          category: 'Database',
        })
      }
    }
  }

  return findings
}
