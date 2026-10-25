import { useEffect, useState } from 'react'

function parse() {
  const h = window.location.hash.replace(/^#/, '') || '/'
  const [pathname, query = ''] = h.split('?')
  return { path: pathname, parts: pathname.split('/').filter(Boolean), query: new URLSearchParams(query) }
}

export function useRoute() {
  const [route, setRoute] = useState(parse)
  useEffect(() => {
    const on = () => setRoute(parse())
    window.addEventListener('hashchange', on)
    return () => window.removeEventListener('hashchange', on)
  }, [])
  return route
}

export const go = to => {
  window.location.hash = to
}
