// ── IaC Security Rules: 15 rules across 5 categories ──

/**
 * Rule catalog for IaC security analysis.
 * Each rule has per-IaC-type regex patterns, severity, confidence, and remediation info.
 * @type {Array<{ id: string, category: string, iacTypes: string[], patterns: Object<string, RegExp>, severity: string, confidence: string, title: string, description: string, fix: string }>}
 */
export const IAC_RULES = [
  // ── Excessive Permissions (3 rules) ──
  {
    id: 'IAC-001',
    category: 'Excessive Permissions',
    iacTypes: ['terraform', 'cloudformation', 'ansible'],
    patterns: {
      terraform: /actions\s*=\s*\[\s*"\*"\s*\]/i,
      cloudformation: /Action:\s*['"]?\*['"]?/i,
      ansible: /action:\s*['"]?\*['"]?/i,
    },
    severity: 'critico',
    confidence: 'high',
    title: 'Acoes IAM com wildcard',
    description: 'Politica IAM com Action: "*" concede todas as permissoes, violando principio de menor privilegio.',
    fix: 'Restringir actions a permissoes especificas necessarias. Ex: ["s3:GetObject", "s3:PutObject"].',
  },
  {
    id: 'IAC-002',
    category: 'Excessive Permissions',
    iacTypes: ['terraform', 'cloudformation'],
    patterns: {
      terraform: /resources\s*=\s*\[\s*"\*"\s*\]/i,
      cloudformation: /Resource:\s*['"]?\*['"]?/i,
    },
    severity: 'critico',
    confidence: 'high',
    title: 'Resource IAM com wildcard',
    description: 'Politica IAM com Resource: "*" se aplica a todos os recursos da conta.',
    fix: 'Restringir Resource a ARNs especificos. Ex: "arn:aws:s3:::my-bucket/*".',
  },
  {
    id: 'IAC-003',
    category: 'Excessive Permissions',
    iacTypes: ['terraform', 'cloudformation', 'ansible'],
    patterns: {
      terraform: /arn:aws:iam::aws:policy\/Administrator/i,
      cloudformation: /arn:aws:iam::aws:policy\/Administrator/i,
      ansible: /policy_arn:.*AdministratorAccess/i,
    },
    severity: 'alto',
    confidence: 'medium',
    title: 'Politica de administrador anexada',
    description: 'Anexar politica AdministratorAccess concede acesso total a conta AWS.',
    fix: 'Criar politica customizada com permissoes minimas necessarias.',
  },

  // ── Public Storage (3 rules) ──
  {
    id: 'IAC-010',
    category: 'Public Storage',
    iacTypes: ['terraform', 'cloudformation', 'ansible'],
    patterns: {
      terraform: /acl\s*=\s*"public-read(?:-write)?"/i,
      cloudformation: /AccessControl:\s*['"]?Public(?:Read|ReadWrite)['"]?/i,
      ansible: /permission:\s*['"]?public-read/i,
    },
    severity: 'critico',
    confidence: 'high',
    title: 'S3 bucket com ACL publica',
    description: 'Bucket S3 configurado com acesso publico via ACL.',
    fix: 'Remover ACL publica. Usar bucket policy restritiva.',
  },
  {
    id: 'IAC-011',
    category: 'Public Storage',
    iacTypes: ['terraform', 'cloudformation'],
    patterns: {
      terraform: /principal\s*=\s*"\*"/i,
      cloudformation: /Principal:\s*['"]?\*['"]?/i,
    },
    severity: 'critico',
    confidence: 'high',
    title: 'Bucket policy com Principal publico',
    description: 'Bucket policy com Principal: "*" permite acesso de qualquer entidade.',
    fix: 'Restringir Principal a ARNs especificos ou condicoes de acesso.',
  },
  {
    id: 'IAC-012',
    category: 'Public Storage',
    iacTypes: ['terraform', 'cloudformation'],
    patterns: {
      terraform: /block_public_acls\s*=\s*false/i,
      cloudformation: /BlockPublicAcls:\s*['"]?false['"]?/i,
    },
    severity: 'alto',
    confidence: 'high',
    title: 'Bloqueio de acesso publico desabilitado',
    description: 'Block public access desabilitado permite ACLs publicas no bucket S3.',
    fix: 'Habilitar block_public_acls = true e demais configuracoes de bloqueio.',
  },

  // ── Missing Encryption (4 rules) ──
  {
    id: 'IAC-020',
    category: 'Missing Encryption',
    iacTypes: ['terraform', 'cloudformation', 'ansible'],
    patterns: {
      terraform: /encrypted\s*=\s*false/i,
      cloudformation: /Encrypted:\s*['"]?false['"]?/i,
      ansible: /encrypt:\s*(?:false|no)/i,
    },
    severity: 'alto',
    confidence: 'high',
    title: 'Criptografia desabilitada',
    description: 'Recurso configurado sem criptografia em repouso.',
    fix: 'Habilitar criptografia. Ex: encrypted = true com KMS key.',
  },
  {
    id: 'IAC-021',
    category: 'Missing Encryption',
    iacTypes: ['terraform', 'cloudformation'],
    patterns: {
      terraform: /encrypted\s*=\s*false/i,
      cloudformation: /Encrypted:\s*['"]?false['"]?/i,
    },
    severity: 'alto',
    confidence: 'high',
    title: 'Volume EBS sem criptografia',
    description: 'Volume EBS configurado sem criptografia em repouso.',
    fix: 'Habilitar encrypted = true no recurso EBS.',
  },
  {
    id: 'IAC-022',
    category: 'Missing Encryption',
    iacTypes: ['terraform', 'cloudformation'],
    patterns: {
      terraform: /storage_encrypted\s*=\s*false/i,
      cloudformation: /StorageEncrypted:\s*['"]?false['"]?/i,
    },
    severity: 'alto',
    confidence: 'high',
    title: 'RDS sem criptografia de armazenamento',
    description: 'Instancia RDS configurada sem criptografia de armazenamento.',
    fix: 'Habilitar storage_encrypted = true na instancia RDS.',
  },
  {
    id: 'IAC-023',
    category: 'Missing Encryption',
    iacTypes: ['terraform'],
    patterns: {
      terraform: /ca_cert_identifier\s*=\s*""/i,
    },
    severity: 'medio',
    confidence: 'medium',
    title: 'RDS sem enforcement de SSL',
    description: 'Instancia RDS sem certificado SSL configurado para conexoes.',
    fix: 'Configurar ca_cert_identifier e parameter group com rds.force_ssl = 1.',
  },

  // ── Open Security Groups (3 rules) ──
  {
    id: 'IAC-030',
    category: 'Open Security Groups',
    iacTypes: ['terraform', 'cloudformation', 'ansible'],
    patterns: {
      terraform: /cidr_blocks\s*=\s*\["0\.0\.0\.0\/0"\]/i,
      cloudformation: /CidrIp:\s*['"]?0\.0\.0\.0\/0['"]?/i,
      ansible: /cidr_ip:\s*['"]?0\.0\.0\.0\/0['"]?/i,
    },
    severity: 'critico',
    confidence: 'high',
    title: 'Security group aberto para internet',
    description: 'Regra de ingress permite trafego de qualquer IP (0.0.0.0/0).',
    fix: 'Restringir CIDR a IPs ou ranges especificos necessarios.',
  },
  {
    id: 'IAC-031',
    category: 'Open Security Groups',
    iacTypes: ['terraform', 'cloudformation', 'ansible'],
    patterns: {
      terraform: /cidr_blocks\s*=\s*\["0\.0\.0\.0\/0"\]/i,
      cloudformation: /CidrIp:\s*['"]?0\.0\.0\.0\/0['"]?/i,
      ansible: /cidr_ip:\s*['"]?0\.0\.0\.0\/0['"]?/i,
    },
    severity: 'alto',
    confidence: 'high',
    title: 'Ingress 0.0.0.0/0 em qualquer porta',
    description: 'Regra de ingress permite trafego de qualquer IP em qualquer porta.',
    fix: 'Restringir CIDR e limitar portas abertas ao minimo necessario.',
  },
  {
    id: 'IAC-032',
    category: 'Open Security Groups',
    iacTypes: ['terraform', 'cloudformation'],
    patterns: {
      terraform: /egress[\s\S]*?cidr_blocks\s*=\s*\["0\.0\.0\.0\/0"\]/im,
      cloudformation: /SecurityGroupEgress[\s\S]*?CidrIp:\s*['"]?0\.0\.0\.0\/0/im,
    },
    severity: 'medio',
    confidence: 'medium',
    title: 'Egress irrestrito para internet',
    description: 'Regra de egress permite trafego para qualquer IP (0.0.0.0/0).',
    fix: 'Restringir egress a destinos necessarios. Considerar VPC endpoints.',
  },

  // ── Hardcoded Secrets (2 rules) ──
  {
    id: 'IAC-040',
    category: 'Hardcoded Secrets',
    iacTypes: ['terraform', 'cloudformation', 'ansible'],
    patterns: {
      terraform: /(?:^|[\s'"=:])AKIA[A-Z0-9]{16}(?:$|[\s'"&])/,
      cloudformation: /(?:^|[\s'"=:])AKIA[A-Z0-9]{16}(?:$|[\s'"&])/,
      ansible: /(?:^|[\s'"=:])AKIA[A-Z0-9]{16}(?:$|[\s'"&])/,
    },
    severity: 'critico',
    confidence: 'high',
    title: 'Chave de acesso AWS hardcoded',
    description: 'Chave de acesso AWS (AKIA...) encontrada em texto plano no codigo.',
    fix: 'Remover chave do codigo. Usar AWS Secrets Manager ou variaveis de ambiente.',
  },
  {
    id: 'IAC-041',
    category: 'Hardcoded Secrets',
    iacTypes: ['terraform', 'cloudformation', 'ansible'],
    patterns: {
      terraform: /password\s*=\s*"[^"]{8,}"/i,
      cloudformation: /Password:\s*['"][^'"]{8,}['"]/i,
      ansible: /password:\s*['"][^'"]{8,}['"]/i,
    },
    severity: 'critico',
    confidence: 'medium',
    title: 'Senha hardcoded em texto plano',
    description: 'Senha encontrada em texto plano no codigo de infraestrutura.',
    fix: 'Usar AWS Secrets Manager, SSM Parameter Store ou variaveis de ambiente.',
  },
]
