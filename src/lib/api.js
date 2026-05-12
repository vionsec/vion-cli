// Thin fetch wrapper for the VION API. Uses native fetch (Node 18+).

class HttpError extends Error {
  constructor(status, body, url) {
    super(`HTTP ${status} ${url}: ${body?.error || body?.message || 'request failed'}`)
    this.status = status
    this.body = body
    this.url = url
  }
}

async function request(method, baseUrl, path, { body, token, headers = {} } = {}) {
  const url = `${baseUrl}${path}`
  const opts = {
    method,
    headers: {
      Accept: 'application/json',
      'User-Agent': '@vionsec/cli',
      ...headers,
    },
  }

  if (token) {
    opts.headers.Authorization = `Bearer ${token}`
  }

  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json'
    opts.body = JSON.stringify(body)
  }

  const res = await fetch(url, opts)
  const text = await res.text()
  let parsed
  try {
    parsed = text ? JSON.parse(text) : {}
  } catch {
    parsed = { error: text }
  }

  if (!res.ok) {
    throw new HttpError(res.status, parsed, url)
  }

  return parsed
}

export function createApi(baseUrl) {
  return {
    post: (path, opts) => request('POST', baseUrl, path, opts),
    get: (path, opts) => request('GET', baseUrl, path, opts),
  }
}

export { HttpError }
