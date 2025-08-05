resource "vsphere_virtual_machine" "test_vm" {
  name   = "test-vm"
  tags   = ["firewall_secured"]

  network_interface {
    network_id = "public-network"
  }

  clone {
    template_uuid = "template-ubuntu-secure-001"

    customize {
      linux_options {
        host_name = "vmtest"
        domain    = "local"
        password  = "verysecurepassword123"
      }
    }
  }
}
