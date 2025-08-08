# rule:
#   id: CUSTOM_VSPHERE_001
#   description: Enforce VM naming convention
#   impact: Non-standard names make VMs hard to track
#   resolution: Use standard naming regex
#   severity: LOW
#   provider: vsphere
#   resource_type: vsphere_virtual_machine
#   checks:
#     - key: name
#       predicate: regex
#       value: "^[a-z]{2}[a-z]{2}[a-z]{1}-[a-z]{2}-[a-z0-9]+$"

package tfsec_custom.CUSTOM_VSPHERE_001

__rego__metadoc__ := {
  "id": "CUSTOM_VSPHERE_001",
  "title": "Enforce VM naming convention",
  "severity": "LOW",
  "description": "Non-standard names make VMs hard to track",
  "recommended_actions": ["Use standard naming regex: ^[a-z]{2}[a-z]{2}[a-z]{1}-[a-z]{2}-[a-z0-9]+$"]
}

deny[res] {
  input.resource_type == "vsphere_virtual_machine"
  res := input.resource
  not regex.match("^[a-z]{2}[a-z]{2}[a-z]{1}-[a-z]{2}-[a-z0-9]+$", res.name)
}
