# terraform-aws-security

Production-ready Terraform modules for a hardened AWS baseline. Demonstrates security engineering principles: least privilege, encryption at rest/in transit, network segmentation, and threat detection.

## Architecture

```
┌─────────────────────────────────────────┐
│  AWS Organization                        │
│  ┌───────────────────────────────────┐  │
│  │  SCP: deny-root, enforce-MFA      │  │
│  │  ┌─────────────────────────────┐  │  │
│  │  │  VPC (3 AZs)                │  │  │
│  │  │  Public / Private / DB tiers│  │  │
│  │  │  NACLs + Security Groups    │  │  │
│  │  └─────────────────────────────┘  │  │
│  │  IAM roles (no wildcard actions)  │  │
│  │  KMS CMK per resource type        │  │
│  │  S3 (versioned, encrypted, MFA-D) │  │
│  │  GuardDuty + CloudTrail + Config  │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

## Modules

| Module | Purpose |
|--------|---------|
| `modules/vpc` | 3-tier VPC with flow logs, NACLs |
| `modules/iam` | Least-privilege roles with permission boundaries |
| `modules/kms` | CMK per service with key rotation |
| `modules/s3` | Encrypted, versioned bucket with MFA Delete |
| `modules/guardduty` | GuardDuty + SNS alerting |

## Usage

```hcl
module "vpc" {
  source             = "./modules/vpc"
  vpc_cidr           = var.vpc_cidr
  availability_zones = var.availability_zones
  environment        = var.environment
}

module "iam" {
  source      = "./modules/iam"
  environment = var.environment
}

module "kms" {
  source      = "./modules/kms"
  environment = var.environment
}
```

## Security Controls Demonstrated

- **Encryption**: KMS CMK for EBS, S3, Secrets Manager; TLS enforced via bucket policy
- **Least Privilege**: IAM roles with permission boundaries; no `*` actions or resources
- **Network Segmentation**: Public/Private/DB subnets; NACLs deny all by default
- **Logging & Detection**: CloudTrail (all regions), VPC Flow Logs, GuardDuty, Config Rules
- **Compliance**: CIS AWS Foundations Benchmark controls

## CI/CD

This repo runs `terraform fmt`, `terraform validate`, `tfsec`, and `checkov` on every PR via GitHub Actions. See `.github/workflows/terraform.yml`.

## Prerequisites

- Terraform >= 1.6
- AWS CLI configured
- S3 backend bucket + DynamoDB lock table pre-created

```bash
terraform init \
  -backend-config="bucket=your-tfstate-bucket" \
  -backend-config="dynamodb_table=your-lock-table"

terraform plan -var-file=terraform.tfvars
terraform apply -var-file=terraform.tfvars
```
