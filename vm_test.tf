resource "vsphere_virtual_machine" "test_vm" {
  name = "csbkp-lx-app1"
  tags = ["firewall_secured"]

  network_interface {
    network_id = "public-network"
  }

  clone {
    template_uuid = "template-ubuntu-secure-001"

    customize {
      linux_options {
        password = "short"  # volontairement trop court pour déclencher l'erreur
      }
    }
  }
}
