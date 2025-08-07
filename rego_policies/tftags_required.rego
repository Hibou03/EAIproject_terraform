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
