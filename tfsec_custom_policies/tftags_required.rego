# rule:
#   id: CUSTOM_VSPHERE_003
#   description: Ensure VM has required tags
#   impact: Missing tags reduce traceability
#   resolution: Add owner and environment tags
#   severity: MEDIUM
#   provider: vsphere
#   resource_type: vsphere_virtual_machine
#   checks:
#     - key: tags.owner
#       predicate: exists
#     - key: tags.environment
#       predicate: exists

package tfsec_custom.CUSTOM_VSPHERE_003

__rego__metadoc__ := {
  "id": "CUSTOM_VSPHERE_003",
  "title": "Ensure VM has required tags",
  "severity": "MEDIUM",
  "description": "Missing tags reduce traceability",
  "recommended_actions": ["Add owner and environment tags"]
}

deny[res] {
  input.resource_type == "vsphere_virtual_machine"
  res := input.resource
  not res.tags.owner
}

deny[res] {
  input.resource_type == "vsphere_virtual_machine"
  res := input.resource
  not res.tags.environment
}
