#Déclaration des variables dans main

variable "vsphere_user"{}
variable "vsphere_password"{}
variable "vsphere_server"{}

variable "datacenter" {}
variable "datastore" {}
variable "cluster" {}
variable "network" {}
variable "template" {}
variable "vm_name" {}
variable "ipv4_adress" {}
variable "ipv4_gateway" {}

variable "linux_admin_password" {
  description = "Password for the Linux VM admin user (must be at least 12 characters)"
  type        = string
  sensitive   = true  # Masque la valeur dans les logs Terraform
}