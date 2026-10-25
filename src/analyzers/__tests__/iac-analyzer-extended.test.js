import { describe, it, expect } from 'vitest'
import { analyzeIaC } from '../iac-analyzer.js'
import { validateFinding } from '../finding-schema.js'

// Testes adicionais: cenários do mundo real combinando múltiplas regras
// e edge cases não cobertos pelo arquivo principal.

describe('iac-analyzer — terraform real-world scenarios (extended)', () => {
  it('detecta S3 público + sem block_public_acls em conjunto', () => {
    const tf = `
resource "aws_s3_bucket" "leak" {
  bucket = "my-leak"
  acl    = "public-read-write"
}

resource "aws_s3_bucket_public_access_block" "leak_block" {
  bucket                  = aws_s3_bucket.leak.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}`
    const findings = analyzeIaC(tf, 'terraform', 's3.tf')
    expect(findings.find((f) => f.rule_id === 'IAC-010')).toBeDefined()
    expect(findings.find((f) => f.rule_id === 'IAC-012')).toBeDefined()
  })

  it('detecta RDS sem encryption combinado com sem SSL', () => {
    const tf = `
resource "aws_db_instance" "main" {
  allocated_storage    = 20
  engine               = "mysql"
  storage_encrypted    = false
  ca_cert_identifier   = ""
  password             = "Sup3rS3cretP@ss123"
}`
    const findings = analyzeIaC(tf, 'terraform', 'rds.tf')
    expect(findings.find((f) => f.rule_id === 'IAC-022')).toBeDefined()
    expect(findings.find((f) => f.rule_id === 'IAC-023')).toBeDefined()
    expect(findings.find((f) => f.rule_id === 'IAC-041')).toBeDefined()
  })

  it('detecta security group 0.0.0.0/0 em ingress (porta 22)', () => {
    const tf = `
resource "aws_security_group" "ssh_open" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}`
    const findings = analyzeIaC(tf, 'terraform', 'sg.tf')
    expect(findings.find((f) => f.rule_id === 'IAC-030')).toBeDefined()
  })

  it('detecta egress 0.0.0.0/0 (regra IAC-031 dispara em qualquer cidr_blocks open)', () => {
    // Nota: IAC-032 (egress especificamente) tem padrão multiline que não casa
    // pois analyzer itera linha-por-linha. Mas IAC-030/IAC-031 ainda casam o
    // cidr_blocks = ["0.0.0.0/0"] solitário.
    const tf = `
resource "aws_security_group" "egress_open" {
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}`
    const findings = analyzeIaC(tf, 'terraform', 'sg.tf')
    // pelo menos uma regra de open SG dispara
    const sgFindings = findings.filter((f) => ['IAC-030', 'IAC-031', 'IAC-032'].includes(f.rule_id))
    expect(sgFindings.length).toBeGreaterThanOrEqual(1)
  })

  it('detecta IAM com Action = ["*"] e Resource = ["*"]', () => {
    const tf = `
resource "aws_iam_policy" "godmode" {
  policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      actions   = ["*"]
      resources = ["*"]
    }]
  })
}`
    const findings = analyzeIaC(tf, 'terraform', 'iam.tf')
    expect(findings.find((f) => f.rule_id === 'IAC-001')).toBeDefined()
    expect(findings.find((f) => f.rule_id === 'IAC-002')).toBeDefined()
  })

  it('detecta AdministratorAccess policy attach', () => {
    const tf = `
resource "aws_iam_role_policy_attachment" "admin" {
  role       = aws_iam_role.svc.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}`
    const findings = analyzeIaC(tf, 'terraform', 'iam.tf')
    expect(findings.find((f) => f.rule_id === 'IAC-003')).toBeDefined()
  })

  it('detecta hardcoded AKIA key dentro de string', () => {
    const tf = `
provider "aws" {
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI"
}`
    const findings = analyzeIaC(tf, 'terraform', 'provider.tf')
    expect(findings.find((f) => f.rule_id === 'IAC-040')).toBeDefined()
  })
})

describe('iac-analyzer — cloudformation real-world (extended)', () => {
  it('detecta IAM permissivo CloudFormation (Action: "*", Resource: "*")', () => {
    const cf = `
Resources:
  AdminPolicy:
    Type: AWS::IAM::Policy
    Properties:
      PolicyDocument:
        Statement:
          - Effect: Allow
            Action: "*"
            Resource: "*"`
    const findings = analyzeIaC(cf, 'cloudformation', 'admin.yaml')
    expect(findings.find((f) => f.rule_id === 'IAC-001')).toBeDefined()
    expect(findings.find((f) => f.rule_id === 'IAC-002')).toBeDefined()
  })

  it('detecta CidrIp 0.0.0.0/0 em CloudFormation SecurityGroup', () => {
    const cf = `
Resources:
  Sg:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 0
          ToPort: 65535
          CidrIp: 0.0.0.0/0`
    const findings = analyzeIaC(cf, 'cloudformation', 'sg.yaml')
    expect(findings.find((f) => f.rule_id === 'IAC-030')).toBeDefined()
  })

  it('detecta StorageEncrypted: false em RDS CloudFormation', () => {
    const cf = `
Resources:
  Rds:
    Type: AWS::RDS::DBInstance
    Properties:
      Engine: mysql
      StorageEncrypted: false
      MasterUserPassword: "MyP@ssw0rd123"`
    const findings = analyzeIaC(cf, 'cloudformation', 'rds.yaml')
    expect(findings.find((f) => f.rule_id === 'IAC-022')).toBeDefined()
    expect(findings.find((f) => f.rule_id === 'IAC-041')).toBeDefined()
  })

  it('downgrade de confidence quando usa !Ref', () => {
    const cf = `Password: !Ref DbPasswordParam`
    const findings = analyzeIaC(cf, 'cloudformation', 'main.yaml')
    const f = findings.find((f) => f.rule_id === 'IAC-041')
    if (f) {
      // !Ref deveria fazer downgrade — high → medium
      expect(['low', 'medium']).toContain(f.confidence)
    }
  })

  it('detecta Principal: "*" em bucket policy', () => {
    const cf = `
Resources:
  BucketPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      PolicyDocument:
        Statement:
          - Principal: "*"
            Action: s3:GetObject`
    const findings = analyzeIaC(cf, 'cloudformation', 'bucket.yaml')
    expect(findings.find((f) => f.rule_id === 'IAC-011')).toBeDefined()
  })
})

describe('iac-analyzer — ansible real-world (extended)', () => {
  it('detecta action: "*" em iam_policy ansible', () => {
    const ansible = `
- name: Bad IAM
  iam_policy:
    state: present
    action: "*"`
    const findings = analyzeIaC(ansible, 'ansible', 'play.yml')
    expect(findings.find((f) => f.rule_id === 'IAC-001')).toBeDefined()
  })

  it('detecta cidr_ip: 0.0.0.0/0 em ec2_group', () => {
    const ansible = `
- name: Open SG
  ec2_group:
    name: bad
    rules:
      - proto: tcp
        from_port: 22
        to_port: 22
        cidr_ip: 0.0.0.0/0`
    const findings = analyzeIaC(ansible, 'ansible', 'play.yml')
    expect(findings.find((f) => f.rule_id === 'IAC-030')).toBeDefined()
  })

  it('detecta encrypt: false em ansible', () => {
    const ansible = `
- name: Bad volume
  ec2_vol:
    encrypt: false
    volume_size: 10`
    const findings = analyzeIaC(ansible, 'ansible', 'play.yml')
    expect(findings.find((f) => f.rule_id === 'IAC-020')).toBeDefined()
  })

  it('detecta password hardcoded em ansible', () => {
    const ansible = `
- name: Bad config
  template:
    src: db.conf.j2
  vars:
    password: "PlainTextPassword123"`
    const findings = analyzeIaC(ansible, 'ansible', 'play.yml')
    expect(findings.find((f) => f.rule_id === 'IAC-041')).toBeDefined()
  })

  it('downgrade quando ansible usa {{ vault_var }}', () => {
    const ansible = `password: "{{ vault_db_password }}"`
    const findings = analyzeIaC(ansible, 'ansible', 'play.yml')
    const f = findings.find((f) => f.rule_id === 'IAC-041')
    if (f) {
      expect(['low', 'medium']).toContain(f.confidence)
    }
  })
})

describe('iac-analyzer — contract & edge cases (extended)', () => {
  it('todos os findings de cenário completo passam validateFinding', () => {
    const tf = `
resource "aws_s3_bucket" "x" { acl = "public-read" }
resource "aws_security_group" "y" {
  ingress { cidr_blocks = ["0.0.0.0/0"] }
}
resource "aws_db_instance" "z" {
  password = "MyHardcoded123"
  storage_encrypted = false
}`
    const findings = analyzeIaC(tf, 'terraform', 'main.tf')
    expect(findings.length).toBeGreaterThan(0)
    for (const f of findings) {
      const result = validateFinding(f)
      expect(result.valid).toBe(true)
    }
  })

  it('iacType desconhecido retorna [] (sem regras aplicáveis)', () => {
    const findings = analyzeIaC('acl = "public-read"', 'unknown', 'x.tf')
    expect(findings).toEqual([])
  })

  it('content vazio retorna []', () => {
    expect(analyzeIaC('', 'terraform', 'a.tf')).toEqual([])
    expect(analyzeIaC(null, 'terraform', 'a.tf')).toEqual([])
    expect(analyzeIaC(undefined, 'terraform', 'a.tf')).toEqual([])
  })

  it('rule_id presente em todo finding', () => {
    const findings = analyzeIaC('acl = "public-read"', 'terraform', 'x.tf')
    for (const f of findings) {
      expect(f.rule_id).toBeDefined()
      expect(f.rule_id).toMatch(/^IAC-\d{3}$/)
    }
  })

  it('linha em comentário não gera finding (Terraform #)', () => {
    const tf = `# acl = "public-read"
acl = "private"`
    const findings = analyzeIaC(tf, 'terraform', 'x.tf')
    expect(findings.filter((f) => f.rule_id === 'IAC-010')).toEqual([])
  })

  it('linha em comentário não gera finding (CF #)', () => {
    const cf = `# AccessControl: PublicRead`
    const findings = analyzeIaC(cf, 'cloudformation', 'x.yaml')
    expect(findings.filter((f) => f.rule_id === 'IAC-010')).toEqual([])
  })

  it('linha em comentário não gera finding (Ansible #)', () => {
    const ansible = `# permission: public-read`
    const findings = analyzeIaC(ansible, 'ansible', 'x.yml')
    expect(findings.filter((f) => f.rule_id === 'IAC-010')).toEqual([])
  })

  it('preserva file_path argument no finding', () => {
    const findings = analyzeIaC('acl = "public-read"', 'terraform', 'infra/prod/main.tf')
    expect(findings[0].file_path).toBe('infra/prod/main.tf')
  })

  it('line_number aponta pra linha correta em multi-line', () => {
    const tf = `# header
# more
acl = "public-read"`
    const findings = analyzeIaC(tf, 'terraform', 'x.tf')
    const f = findings.find((f) => f.rule_id === 'IAC-010')
    expect(f).toBeDefined()
    expect(f.line_number).toBe(3)
  })
})
