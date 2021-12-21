# Aviatrix Controller Build

This module builds and launches the Aviatrix Controller VM instance.

## Providers

| Name | Version |
|------|---------|
| <a name="provider_azurerm"></a> [azurerm](#provider\_azurerm) | >= 2.0 |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [azurerm_linux_virtual_machine.aviatrix_controller_vm](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/linux_virtual_machine) | resource |
| [azurerm_network_interface.aviatrix_controller_nic](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_interface) | resource |
| [azurerm_network_security_group.aviatrix_controller_nsg](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_security_group) | resource |
| [azurerm_public_ip.aviatrix_controller_public_ip](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/public_ip) | resource |
| [azurerm_resource_group.aviatrix_controller_rg](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/resource_group) | resource |
| [azurerm_subnet.aviatrix_controller_subnet](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/subnet) | resource |
| [azurerm_virtual_network.aviatrix_controller_vnet](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_network) | resource |
| [azurerm_public_ip.aviatrix_controller_public_ip_address](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/data-sources/public_ip) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_controller_name"></a> [controller\_name](#input\_controller\_name) | Customized Name for Aviatrix Controller | `string` | n/a | yes |
| <a name="input_controller_subnet_cidr"></a> [controller\_subnet\_cidr](#input\_controller\_subnet\_cidr) | CIDR for controller subnet. | `string` | `"10.0.0.0/24"` | no |
| <a name="input_controller_virtual_machine_admin_password"></a> [controller\_virtual\_machine\_admin\_password](#input\_controller\_virtual\_machine\_admin\_password) | Admin Password for the controller virtual machine. | `string` | `"aviatrix1234!"` | no |
| <a name="input_controller_virtual_machine_admin_username"></a> [controller\_virtual\_machine\_admin\_username](#input\_controller\_virtual\_machine\_admin\_username) | Admin Username for the controller virtual machine. | `string` | `"aviatrix"` | no |
| <a name="input_controller_virtual_machine_size"></a> [controller\_virtual\_machine\_size](#input\_controller\_virtual\_machine\_size) | Virtual Machine size for the controller. | `string` | `"Standard_A4_v2"` | no |
| <a name="input_controller_vnet_cidr"></a> [controller\_vnet\_cidr](#input\_controller\_vnet\_cidr) | CIDR for controller VNET. | `string` | `"10.0.0.0/24"` | no |
| <a name="input_location"></a> [location](#input\_location) | Resource Group Location for Aviatrix Controller | `string` | `"West US"` | no |
| <a name="input_incoming_ssl_cidr"></a> [incoming_ssl_cidr](#input\_incoming\_ssl\_cidr) | List of incoming cidrs for network security group used by controller. | `list(string)` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_aviatrix_controller_private_ip_address"></a> [aviatrix\_controller\_private\_ip\_address](#output\_aviatrix\_controller\_private\_ip\_address) | n/a |
| <a name="output_aviatrix_controller_public_ip_address"></a> [aviatrix\_controller\_public\_ip\_address](#output\_aviatrix\_controller\_public\_ip\_address) | n/a |
| <a name="output_aviatrix_controller_vnet"></a> [aviatrix\_controller\_vnet](#output\_aviatrix\_controller\_vnet) | n/a |
| <a name="output_aviatrix_controller_rg"></a> [aviatrix\_controller\_rg](#output\_aviatrix\_controller\_rg) | n/a |