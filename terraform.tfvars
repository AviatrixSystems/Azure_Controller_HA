app_name = "Avx_ctrl_ha"
controller_name = "avxcontroller"
location = "EAST US"
controller_virtual_machine_size = "Standard_A4_v2"
controller_vnet_cidr = "10.0.0.0/23"
controller_subnet_cidr = "10.0.0.0/27"
incoming_ssl_cidr = ["173.172.186.204"]
subscription_id           = "d064bacd-49d6-4e0f-8d5b-7c62c50a686f"
controller_virtual_machine_admin_username = "pranaybomma"
controller_virtual_machine_admin_password = "Pp6099379600$"
avx_controller_admin_email = "pbomma@aviatrix.com"
account_email = "pbomma@aviatrix.com"
avx_controller_admin_password = "Pp6099379600$"
access_account_name = "pbomma-azure"
aviatrix_customer_id = "carmelodev-1393702544.64"
controller_version = "6.5"

copilot_name = "avxcopilot"
copilot_virtual_machine_size = "Standard_A4_v2" 
copilot_disk_size_gb = 20 
# copilot_subnet_cidr = "10.0.1.0/24"
copilot_virtual_machine_admin_username = "pranaybomma"
copilot_virtual_machine_admin_password = "Pp6099379600$"
copilot_allowed_cidrs = {
  "tcp_cidrs" = {
    priority = "101"
    protocol = "tcp"
    ports    = ["443"]
    cidrs    = ["0.0.0.0/0"]
  }
  "udp_cidrs" = {
    priority = "102"
    protocol = "udp"
    ports    = ["5000", "31283"]
    cidrs    = ["0.0.0.0/0"]
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


