# policies/iam-no-wildcard.rego
# Deny any IAM policy in the Terraform plan that uses a wildcard ("*")
# for both Action AND Resource in the same Allow statement.
# This is the classic "admin by accident" pattern.
# CIS AWS Foundations Benchmark 1.16

package terraform

import future.keywords.contains
import future.keywords.if

# Helper: normalise Action to a set (it can be a string or list)
actions_set(stmt) := {stmt.Action} if is_string(stmt.Action)
actions_set(stmt) := {a | a := stmt.Action[_]} if is_array(stmt.Action)

# Helper: normalise Resource the same way
resources_set(stmt) := {stmt.Resource} if is_string(stmt.Resource)
resources_set(stmt) := {r | r := stmt.Resource[_]} if is_array(stmt.Resource)

# Collect statements from inline and managed policies being applied
policy_statements[address] = stmts if {
  resource := input.resource_changes[_]
  resource.type in ["aws_iam_policy", "aws_iam_role_policy"]
  resource.change.actions[_] in ["create", "update"]
  address := resource.address
  doc := json.unmarshal(resource.change.after.policy)
  stmts := doc.Statement
}

deny contains msg if {
  stmts := policy_statements[address]
  stmt := stmts[_]
  stmt.Effect == "Allow"

  # Wildcard action
  actions := actions_set(stmt)
  actions["*"]

  # Wildcard resource
  resources := resources_set(stmt)
  resources["*"]

  msg := sprintf(
    "DENY [CIS 1.16] IAM policy at '%v' contains Allow * on * — this grants full admin access. Use least-privilege actions and specific resource ARNs.",
    [address],
  )
}
