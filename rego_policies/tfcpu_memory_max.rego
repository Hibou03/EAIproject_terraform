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
