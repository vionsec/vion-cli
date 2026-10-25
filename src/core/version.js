import fs from 'node:fs'
import path from 'node:path'
import { PKG_ROOT } from './paths.js'

export const VERSION = JSON.parse(fs.readFileSync(path.join(PKG_ROOT, 'package.json'), 'utf8')).version
