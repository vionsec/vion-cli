import { describe, it, expect } from 'vitest'
import { analyzeIaC } from '../iac-analyzer.js'
import { validateFinding } from '../finding-schema.js'

// ── Test Fixtures ──

const TF_MULTI_ISSUE = `resource "aws_s3_bucket" "bad" {
  acl = "public-read"
}

resource "aws_security_group" "open" {
  ingress {
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# This should NOT be flagged:
# password = "FAKE_hardcoded123"

resource "aws_db_instance" "db" {
  password          = "FAKE_SuperSecret123"
  storage_encrypted = false
}`

const CF_FIXTURE = `Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicRead
  MyPolicy:
    Type: AWS::IAM::Policy
    Properties:
      PolicyDocument:
        Statement:
          - Effect: Allow
            Action: "*"
            Resource: "*"
  MySecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          CidrIp: 0.0.0.0/0
  MyVolume:
    Type: AWS::EC2::Volume
    Properties:
      Encrypted: false`

const ANSIBLE_FIXTURE = `- name: Create IAM policy
  iam_policy:
    policy_name: admin
    action: "*"
    state: present

- name: Create S3 bucket
  s3_bucket:
    name: my-bucket
    permission: public-read

- name: Create security group
  ec2_group:
    name: open-sg
    rules:
      - proto: tcp
        from_port: 22
        cidr_ip: 0.0.0.0/0`

describe('iac-analyzer', () => {
  describe('terraform analysis (SCAN-01)', () => {
    it('detects public S3 bucket ACL (IAC-010)', () => {
      const findings = analyzeIaC('  acl = "public-read"', 'terraform', 'main.tf')
      const match = findings.find(f => f.rule_id === 'IAC-010')
      expect(match).toBeDefined()
      expect(match.severity).toBe('critico')
    })

    it('detects wildcard IAM actions (IAC-001)', () => {
      const findings = analyzeIaC('  actions = ["*"]', 'terraform', 'main.tf')
      const match = findings.find(f => f.rule_id === 'IAC-001')
      expect(match).toBeDefined()
    })

    it('detects open security group on port 22 (IAC-030)', () => {
      const findings = analyzeIaC('    cidr_blocks = ["0.0.0.0/0"]', 'terraform', 'main.tf')
      const match = findings.find(f => f.rule_id === 'IAC-030')
      expect(match).toBeDefined()
      expect(match.severity).toBe('critico')
    })

    it('detects hardcoded password (IAC-041)', () => {
      const findings = analyzeIaC('  password = "FAKE_SuperSecret123"', 'terraform', 'main.tf')
      const match = findings.find(f => f.rule_id === 'IAC-041')
      expect(match).toBeDefined()
      expect(match.severity).toBe('critico')
    })

    it('detects hardcoded AWS key (IAC-040)', () => {
      const findings = analyzeIaC('  access_key = "AKIAIOSFODNN7EXAMPLE"', 'terraform', 'main.tf')
      const match = findings.find(f => f.rule_id === 'IAC-040')
      expect(match).toBeDefined()
    })

    it('detects storage_encrypted = false (IAC-022)', () => {
      const findings = analyzeIaC('  storage_encrypted = false', 'terraform', 'main.tf')
      const match = findings.find(f => f.rule_id === 'IAC-022')
      expect(match).toBeDefined()
    })

    it('returns correct line_number for each finding', () => {
      const findings = analyzeIaC(TF_MULTI_ISSUE, 'terraform', 'main.tf')
      const iac010 = findings.find(f => f.rule_id === 'IAC-010')
      expect(iac010.line_number).toBe(2)
      const iac030 = findings.find(f => f.rule_id === 'IAC-030')
      expect(iac030.line_number).toBe(9)
      const iac041 = findings.find(f => f.rule_id === 'IAC-041')
      expect(iac041.line_number).toBe(17)
      const iac022 = findings.find(f => f.rule_id === 'IAC-022')
      expect(iac022.line_number).toBe(18)
    })

    it('returns correct code_snippet for each finding', () => {
      const findings = analyzeIaC(TF_MULTI_ISSUE, 'terraform', 'main.tf')
      const iac010 = findings.find(f => f.rule_id === 'IAC-010')
      expect(iac010.code_snippet).toContain('public-read')
    })

    it('returns correct file_path propagated from argument', () => {
      const findings = analyzeIaC('  acl = "public-read"', 'terraform', 'infra/main.tf')
      expect(findings[0].file_path).toBe('infra/main.tf')
    })
  })

  describe('cloudformation analysis (SCAN-02)', () => {
    it('detects Action: "*" (IAC-001)', () => {
      const findings = analyzeIaC(CF_FIXTURE, 'cloudformation', 'stack.yaml')
      const match = findings.find(f => f.rule_id === 'IAC-001')
      expect(match).toBeDefined()
    })

    it('detects AccessControl: PublicRead (IAC-010)', () => {
      const findings = analyzeIaC(CF_FIXTURE, 'cloudformation', 'stack.yaml')
      const match = findings.find(f => f.rule_id === 'IAC-010')
      expect(match).toBeDefined()
    })

    it('detects CidrIp: 0.0.0.0/0 (IAC-030)', () => {
      const findings = analyzeIaC(CF_FIXTURE, 'cloudformation', 'stack.yaml')
      const match = findings.find(f => f.rule_id === 'IAC-030')
      expect(match).toBeDefined()
    })

    it('detects Encrypted: false (IAC-021)', () => {
      const findings = analyzeIaC(CF_FIXTURE, 'cloudformation', 'stack.yaml')
      const match = findings.find(f => f.rule_id === 'IAC-020' || f.rule_id === 'IAC-021')
      expect(match).toBeDefined()
    })
  })

  describe('ansible analysis (SCAN-03)', () => {
    it('detects action: "*" in iam_policy (IAC-001)', () => {
      const findings = analyzeIaC(ANSIBLE_FIXTURE, 'ansible', 'playbook.yml')
      const match = findings.find(f => f.rule_id === 'IAC-001')
      expect(match).toBeDefined()
    })

    it('detects cidr_ip: 0.0.0.0/0 (IAC-030)', () => {
      const findings = analyzeIaC(ANSIBLE_FIXTURE, 'ansible', 'playbook.yml')
      const match = findings.find(f => f.rule_id === 'IAC-030')
      expect(match).toBeDefined()
    })

    it('detects permission: public-read (IAC-010)', () => {
      const findings = analyzeIaC(ANSIBLE_FIXTURE, 'ansible', 'playbook.yml')
      const match = findings.find(f => f.rule_id === 'IAC-010')
      expect(match).toBeDefined()
    })
  })

  describe('comment filtering (SCAN-04)', () => {
    it('ignores terraform # commented code', () => {
      const findings = analyzeIaC('# acl = "public-read"', 'terraform', 'main.tf')
      expect(findings.filter(f => f.rule_id === 'IAC-010')).toHaveLength(0)
    })

    it('ignores terraform // commented code', () => {
      const findings = analyzeIaC('// acl = "public-read"', 'terraform', 'main.tf')
      expect(findings.filter(f => f.rule_id === 'IAC-010')).toHaveLength(0)
    })

    it('ignores terraform /* */ block commented code', () => {
      const input = '/*\nacl = "public-read"\n*/'
      const findings = analyzeIaC(input, 'terraform', 'main.tf')
      expect(findings.filter(f => f.rule_id === 'IAC-010')).toHaveLength(0)
    })

    it('ignores cloudformation # commented code', () => {
      const findings = analyzeIaC('# AccessControl: PublicRead', 'cloudformation', 'stack.yaml')
      expect(findings.filter(f => f.rule_id === 'IAC-010')).toHaveLength(0)
    })

    it('ignores ansible # commented code', () => {
      const findings = analyzeIaC('# permission: public-read', 'ansible', 'playbook.yml')
      expect(findings.filter(f => f.rule_id === 'IAC-010')).toHaveLength(0)
    })

    it('commented line in multi-issue fixture produces no finding', () => {
      const findings = analyzeIaC(TF_MULTI_ISSUE, 'terraform', 'main.tf')
      // Lines 14 and 15 are comments -- no finding on those lines
      const commentFindings = findings.filter(f => f.line_number === 14 || f.line_number === 15)
      expect(commentFindings).toHaveLength(0)
    })
  })

  describe('confidence scoring (SCAN-04)', () => {
    it('keeps high confidence for literal AWS access key', () => {
      const findings = analyzeIaC('access_key = "AKIAIOSFODNN7EXAMPLE"', 'terraform', 'main.tf')
      const match = findings.find(f => f.rule_id === 'IAC-040')
      expect(match).toBeDefined()
      expect(match.confidence).toBe('high')
    })

    it('downgrades confidence for terraform ${var.xxx} interpolation', () => {
      const findings = analyzeIaC('password = "${var.db_password}"', 'terraform', 'main.tf')
      const match = findings.find(f => f.rule_id === 'IAC-041')
      if (match) {
        expect(match.confidence).toBe('low')
      }
    })

    it('downgrades confidence for cloudformation !Ref intrinsic', () => {
      const findings = analyzeIaC('Password: !Ref MySecretParam', 'cloudformation', 'stack.yaml')
      const match = findings.find(f => f.rule_id === 'IAC-041')
      if (match) {
        expect(match.confidence).toBe('low')
      }
    })

    it('downgrades confidence for ansible {{ }} interpolation', () => {
      const findings = analyzeIaC('password: "{{ vault_db_password }}"', 'ansible', 'playbook.yml')
      const match = findings.find(f => f.rule_id === 'IAC-041')
      if (match) {
        expect(match.confidence).toBe('low')
      }
    })
  })

  describe('finding contract compliance', () => {
    it('every finding from terraform multi-issue fixture passes validateFinding()', () => {
      const findings = analyzeIaC(TF_MULTI_ISSUE, 'terraform', 'main.tf')
      expect(findings.length).toBeGreaterThan(0)
      for (const f of findings) {
        const { valid, errors } = validateFinding(f)
        expect(errors).toEqual([])
        expect(valid).toBe(true)
      }
    })

    it('every finding from cloudformation fixture passes validateFinding()', () => {
      const findings = analyzeIaC(CF_FIXTURE, 'cloudformation', 'stack.yaml')
      expect(findings.length).toBeGreaterThan(0)
      for (const f of findings) {
        const { valid, errors } = validateFinding(f)
        expect(errors).toEqual([])
        expect(valid).toBe(true)
      }
    })

    it('every finding from ansible fixture passes validateFinding()', () => {
      const findings = analyzeIaC(ANSIBLE_FIXTURE, 'ansible', 'playbook.yml')
      expect(findings.length).toBeGreaterThan(0)
      for (const f of findings) {
        const { valid, errors } = validateFinding(f)
        expect(errors).toEqual([])
        expect(valid).toBe(true)
      }
    })
  })

  describe('edge cases', () => {
    it('returns empty array for clean terraform content', () => {
      const clean = 'resource "aws_s3_bucket" "b" {\n  acl = "private"\n}'
      const findings = analyzeIaC(clean, 'terraform', 'main.tf')
      expect(findings).toEqual([])
    })

    it('returns empty array for empty string', () => {
      const findings = analyzeIaC('', 'terraform', 'main.tf')
      expect(findings).toEqual([])
    })

    it('only evaluates rules matching the given iacType', () => {
      // IAC-023 is terraform-only -- should not fire for cloudformation
      const findings = analyzeIaC('ca_cert_identifier = ""', 'cloudformation', 'stack.yaml')
      const match = findings.find(f => f.rule_id === 'IAC-023')
      expect(match).toBeUndefined()
    })
  })
})
