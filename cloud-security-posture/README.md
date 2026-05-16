# cloud-security-posture

Policy-as-code enforcement using Open Policy Agent (OPA) and automated CIS benchmark auditing. Demonstrates that security requirements can be expressed as testable, version-controlled code — not tribal knowledge.

## Structure

```
policies/          OPA/Rego policies — evaluated against Terraform plan JSON
  s3-public-block.rego
  iam-no-wildcard.rego
  sg-no-open-ingress.rego
  encryption-required.rego

audit/             Python scripts for CIS AWS Foundations checks
  cis_checks.py
  findings_report.py

docs/
  findings-report.md    Example output from a real audit run
```

## How policies work

1. `terraform plan -out=tfplan` → `terraform show -json tfplan > plan.json`
2. `opa eval --data policies/ --input plan.json "data.terraform.deny"`
3. If `deny` set is non-empty, the pipeline fails with a clear message

## Running OPA locally

```bash
# Install OPA
brew install opa         # macOS
# or
curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
chmod +x opa && sudo mv opa /usr/local/bin/

# Evaluate all deny rules against a plan
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
opa eval \
  --data policies/ \
  --input plan.json \
  --format pretty \
  "data.terraform.deny"

# Unit-test the policies themselves
opa test policies/ -v
```

## CIS Benchmark Checks

`audit/cis_checks.py` runs read-only AWS API calls and maps findings to CIS AWS Foundations Benchmark v1.5 controls.

```bash
pip install boto3 rich
python audit/cis_checks.py --profile your-aws-profile --region us-east-1
```

Output: colour-coded terminal table + `findings-report.md`
