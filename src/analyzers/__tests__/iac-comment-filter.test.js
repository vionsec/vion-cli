import { describe, it, expect } from 'vitest'
import { parseLines } from '../iac-comment-filter.js'

describe('iac-comment-filter', () => {
  describe('terraform', () => {
    it('marks # lines as comments', () => {
      const lines = parseLines('# this is a comment\nresource "aws" {}', 'terraform')
      expect(lines[0].isComment).toBe(true)
      expect(lines[0].lineNum).toBe(1)
    })

    it('marks // lines as comments', () => {
      const lines = parseLines('// this is a comment\nresource "aws" {}', 'terraform')
      expect(lines[0].isComment).toBe(true)
      expect(lines[1].isComment).toBe(false)
    })

    it('marks /* */ block comments spanning multiple lines', () => {
      const input = '/* start\nacl = "public-read"\n*/'
      const lines = parseLines(input, 'terraform')
      expect(lines[0].isComment).toBe(true)
      expect(lines[1].isComment).toBe(true)
      expect(lines[2].isComment).toBe(true)
    })

    it('handles single-line /* */ block comments', () => {
      const lines = parseLines('/* single block */ real code', 'terraform')
      expect(lines[0].isComment).toBe(true)
    })

    it('preserves non-comment lines with isComment: false', () => {
      const lines = parseLines('resource "aws_s3_bucket" "b" {\n  acl = "private"\n}', 'terraform')
      expect(lines[0].isComment).toBe(false)
      expect(lines[1].isComment).toBe(false)
      expect(lines[2].isComment).toBe(false)
    })

    it('returns correct 1-based lineNum for each line', () => {
      const lines = parseLines('line1\nline2\nline3', 'terraform')
      expect(lines[0].lineNum).toBe(1)
      expect(lines[1].lineNum).toBe(2)
      expect(lines[2].lineNum).toBe(3)
    })
  })

  describe('cloudformation', () => {
    it('marks # lines as comments', () => {
      const lines = parseLines('# comment\nResources:', 'cloudformation')
      expect(lines[0].isComment).toBe(true)
      expect(lines[1].isComment).toBe(false)
    })

    it('does not treat // as comments in YAML', () => {
      const lines = parseLines('// not a comment in yaml', 'cloudformation')
      expect(lines[0].isComment).toBe(false)
    })

    it('preserves non-comment lines', () => {
      const lines = parseLines('Resources:\n  MyBucket:\n    Type: AWS::S3::Bucket', 'cloudformation')
      for (const line of lines) {
        expect(line.isComment).toBe(false)
      }
    })
  })

  describe('ansible', () => {
    it('marks # lines as comments', () => {
      const lines = parseLines('# ansible comment\n- name: task', 'ansible')
      expect(lines[0].isComment).toBe(true)
      expect(lines[1].isComment).toBe(false)
    })

    it('preserves non-comment lines', () => {
      const lines = parseLines('- name: deploy\n  hosts: all', 'ansible')
      for (const line of lines) {
        expect(line.isComment).toBe(false)
      }
    })
  })

  describe('edge cases', () => {
    it('returns empty array for empty content', () => {
      const lines = parseLines('', 'terraform')
      expect(lines).toEqual([])
    })

    it('handles inline comments after code (line is NOT marked as comment)', () => {
      const lines = parseLines('acl = "private" # inline comment', 'terraform')
      expect(lines[0].isComment).toBe(false)
    })

    it('preserves line numbers in mixed content', () => {
      const input = '# comment\nreal code\n/* block\nmore block\n*/\nafter block'
      const lines = parseLines(input, 'terraform')
      expect(lines).toHaveLength(6)
      expect(lines[0]).toEqual({ lineNum: 1, text: '# comment', isComment: true })
      expect(lines[1]).toEqual({ lineNum: 2, text: 'real code', isComment: false })
      expect(lines[2]).toEqual({ lineNum: 3, text: '/* block', isComment: true })
      expect(lines[3]).toEqual({ lineNum: 4, text: 'more block', isComment: true })
      expect(lines[4]).toEqual({ lineNum: 5, text: '*/', isComment: true })
      expect(lines[5]).toEqual({ lineNum: 6, text: 'after block', isComment: false })
    })
  })
})
