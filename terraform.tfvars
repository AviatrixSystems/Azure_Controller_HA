app_name                        = "Avx_controller_ha"
controller_name                 = "AvxController"
location                        = "EAST US"
controller_virtual_machine_size = "Standard_A4_v2"
controller_vnet_cidr            = "10.2.0.0/23"
controller_subnet_cidr          = "10.2.0.0/24"
incoming_ssl_cidr               = ["x.x.x.x"]

subscription_id = "******"

controller_virtual_machine_admin_username = "******"
controller_virtual_machine_admin_password = "******"

avx_controller_admin_email    = "******"
account_email                 = "******"
avx_controller_admin_password = "******"
access_account_name           = "******"
aviatrix_customer_id          = "******"
controller_version            = "6.5"


copilot_name = "AvxCopilot"
copilot_virtual_machine_size = "Standard_A4_v2" 
copilot_virtual_machine_admin_username = "******"
copilot_virtual_machine_admin_password = "******"
copilot_allowed_cidrs = {
  "tcp_cidrs" = {
    priority = "101"
    protocol = "tcp"
    ports    = ["443"]
    cidrs    = [""]
  }
  "udp_cidrs" = {
    priority = "102"
    protocol = "udp"
    ports    = ["5000", "31283"]
    cidrs    = [""]
  }
}

copilot_additional_disks = {
  "one" = {
    disk_size_gb = "20"
    lun = "0"
  }
  "two" = {
    disk_size_gb = "20"
    lun = "1"
  }
}


