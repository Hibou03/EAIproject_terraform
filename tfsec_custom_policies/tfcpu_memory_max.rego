# rule:
#   id: CUSTOM_VSPHERE_002
#   description: Enforce maximum CPU and Memory limits
#   impact: Excess resources waste costs
#   resolution: Limit CPU ≤ 4 and Memory ≤ 2048MB
#   severity: HIGH
#   provider: vsphere
#   resource_type: vsphere_virtual_machine
#   checks:
#     - key: num_cpus
#       predicate: lte
#       value: 4
#     - key: memory
#       predicate: lte
#       value: 2048

package tfsec_custom.CUSTOM_VSPHERE_002

__rego__metadoc__ := {
  "id": "CUSTOM_VSPHERE_002",
  "title": "Enforce maximum CPU and Memory limits",
  "severity": "HIGH",
  "description": "Excess resources waste costs",
  "recommended_actions": ["Limit CPU ≤ 4 and Memory ≤ 2048MB"]
}

deny[res] {
  input.resource_type == "vsphere_virtual_machine"
  res := input.resource
  res.num_cpus > 4
}

deny[res] {
  input.resource_type == "vsphere_virtual_machine"
  res := input.resource
  res.memory > 2048
}
