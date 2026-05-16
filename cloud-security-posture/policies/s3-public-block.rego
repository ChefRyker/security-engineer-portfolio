# policies/s3-public-block.rego
# Deny any S3 bucket in the Terraform plan that does not have all
# four public-access-block settings set to true.
# CIS AWS Foundations Benchmark 2.1.5

package terraform

import future.keywords.contains
import future.keywords.if

# Collect all aws_s3_bucket_public_access_block resources from the plan
s3_public_access_blocks[address] = resource if {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket_public_access_block"
  resource.change.actions[_] in ["create", "update"]
  address := resource.address
}

# Build a set of bucket names that HAVE a compliant block resource
compliant_buckets contains bucket_id if {
  block := s3_public_access_blocks[_]
  after := block.change.after
  after.block_public_acls == true
  after.block_public_policy == true
  after.ignore_public_acls == true
  after.restrict_public_buckets == true
  bucket_id := after.bucket
}

# Deny buckets that are being created/updated without a compliant block
deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket"
  resource.change.actions[_] in ["create", "update"]

  bucket_id := resource.change.after.bucket
  not compliant_buckets[bucket_id]

  msg := sprintf(
    "DENY [CIS 2.1.5] S3 bucket '%v' (%v) must have all four public access block settings enabled.",
    [bucket_id, resource.address],
  )
}
