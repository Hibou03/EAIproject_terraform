package tfsec_custom.CUSTOM_VSPHERE_002

__rego__metadoc__ := {
  "id": "CUSTOM_VSPHERE_002",
  "title": "Enforce maximum CPU and Memory limits",
  "severity": "HIGH",
  "description": "Excess resources waste costs",
  "recommended_actions": ["Limit CPU ≤ 4 and Memory ≤ 2048MB"]
}

deny[result] {
  input.resource_type == "vsphere_virtual_machine"
  input.resource.num_cpus > 4

  result := {
    "msg": sprintf("CPU count too high (%v cores)", [input.resource.num_cpus]),
    "metadata": __rego__metadoc__,
  }
}

deny[result] {
  input.resource_type == "vsphere_virtual_machine"
  input.resource.memory > 2048

  result := {
    "msg": sprintf("Memory too high (%v MB)", [input.resource.memory]),
    "metadata": __rego__metadoc__,
  }
}
