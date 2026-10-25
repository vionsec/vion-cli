// ── Finding Contract: canonical vulnerability shape ──

export const REQUIRED_FIELDS = ['severity', 'title', 'description', 'fix', 'category']

export const OPTIONAL_FIELDS = ['confidence', 'file_path', 'line_number', 'code_snippet']

export const VALID_SEVERITIES = ['critico', 'alto', 'medio', 'baixo']

export const VALID_CONFIDENCES = ['high', 'medium', 'low']

/**
 * Validate a finding object against the canonical contract.
 * @param {object} obj — finding object to validate
 * @returns {{ valid: boolean, errors: string[] }}
 */
export function validateFinding(obj) {
  const errors = []

  // Check required fields are present and non-empty strings (category just needs to be present)
  for (const field of REQUIRED_FIELDS) {
    if (obj[field] === undefined || obj[field] === null) {
      errors.push(`Missing required field: ${field}`)
    } else if (field !== 'category' && (typeof obj[field] !== 'string' || obj[field].trim() === '')) {
      errors.push(`Required field '${field}' must be a non-empty string`)
    }
  }

  // Validate severity value
  if (obj.severity !== undefined && obj.severity !== null && !VALID_SEVERITIES.includes(obj.severity)) {
    errors.push(`Invalid severity '${obj.severity}', must be one of: ${VALID_SEVERITIES.join(', ')}`)
  }

  // Validate optional confidence
  if (obj.confidence !== undefined && obj.confidence !== null && !VALID_CONFIDENCES.includes(obj.confidence)) {
    errors.push(`Invalid confidence '${obj.confidence}', must be one of: ${VALID_CONFIDENCES.join(', ')}`)
  }

  // Validate optional line_number
  if (obj.line_number !== undefined && obj.line_number !== null) {
    if (!Number.isInteger(obj.line_number) || obj.line_number < 1) {
      errors.push(`Invalid line_number '${obj.line_number}', must be a positive integer`)
    }
  }

  return { valid: errors.length === 0, errors }
}
