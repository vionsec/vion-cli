// ── IaC Comment Filter: marks lines as comment/non-comment per IaC type ──

const TF_LINE_COMMENT = /^\s*(?:#|\/\/)/
const TF_BLOCK_COMMENT_START = /\/\*/
const TF_BLOCK_COMMENT_END = /\*\//

/**
 * Parse content into annotated lines with comment detection.
 * @param {string} content - Raw file content
 * @param {string} iacType - 'terraform' | 'cloudformation' | 'ansible'
 * @returns {Array<{ lineNum: number, text: string, isComment: boolean }>}
 */
export function parseLines(content, iacType) {
  if (!content) return []

  const lines = content.split('\n')
  const result = []
  let inBlockComment = false

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    let isComment = false

    if (iacType === 'terraform') {
      if (inBlockComment) {
        isComment = true
        if (TF_BLOCK_COMMENT_END.test(line)) inBlockComment = false
      } else if (TF_BLOCK_COMMENT_START.test(line)) {
        isComment = true
        if (!TF_BLOCK_COMMENT_END.test(line)) {
          inBlockComment = true
        }
      } else if (TF_LINE_COMMENT.test(line)) {
        isComment = true
      }
    } else {
      // YAML (CloudFormation + Ansible) -- # single-line only
      if (/^\s*#/.test(line)) isComment = true
    }

    result.push({ lineNum: i + 1, text: line, isComment })
  }

  return result
}
