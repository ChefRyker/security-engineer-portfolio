# policies/sg-no-open-ingress.rego
# Deny security group rules that allow unrestricted inbound access
# (0.0.0.0/0 or ::/0) on sensitive ports.
# CIS AWS Foundations Benchmark 5.2 / 5.3

package terraform

import future.keywords.contains
import future.keywords.if

# Ports that must never be open to the world
sensitive_ports := {22, 3389, 3306, 5432, 6379, 27017}

open_cidrs := {"0.0.0.0/0", "::/0"}

# Evaluate aws_security_group inline ingress rules
deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "aws_security_group"
  resource.change.actions[_] in ["create", "update"]

  rule := resource.change.after.ingress[_]

  # Unrestricted source
  open_cidrs[rule.cidr_blocks[_]]

  # Sensitive port in range
  port := sensitive_ports[_]
  rule.from_port <= port
  rule.to_port >= port

  msg := sprintf(
    "DENY [CIS 5.2/5.3] Security group '%v' allows unrestricted inbound access on port %v (0.0.0.0/0 or ::/0). Restrict to known CIDR ranges.",
    [resource.address, port],
  )
}

# Also catch standalone aws_security_group_rule resources
deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "aws_security_group_rule"
  resource.change.actions[_] in ["create", "update"]

  after := resource.change.after
  after.type == "ingress"
  open_cidrs[after.cidr_blocks[_]]

  port := sensitive_ports[_]
  after.from_port <= port
  after.to_port >= port

  msg := sprintf(
    "DENY [CIS 5.2/5.3] Security group rule '%v' allows unrestricted inbound on port %v.",
    [resource.address, port],
  )
}
