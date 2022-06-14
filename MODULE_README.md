<!-- BEGIN_TF_DOCS -->
## Requirements

No requirements.

## Providers

No providers.

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_aviatrix_controller_azure"></a> [aviatrix\_controller\_azure](#module\_aviatrix\_controller\_azure) | ./aviatrix_controller_ha | n/a |

## Resources

No resources.

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_app_service_plan_name"></a> [app\_service\_plan\_name](#input\_app\_service\_plan\_name) | The name of the app service plan to be deployed. | `string` | `"aviatrix-function-app-sp"` | no |
| <a name="input_application_insights_name"></a> [application\_insights\_name](#input\_application\_insights\_name) | The name of the application insights to be deployed for the function app. | `string` | `"aviatrix-function-app-insights"` | no |
| <a name="input_aviatrix_controller_security_group_allowed_ips"></a> [aviatrix\_controller\_security\_group\_allowed\_ips](#input\_aviatrix\_controller\_security\_group\_allowed\_ips) | Incoming cidr for security group used by controller | `list(string)` | n/a | yes |
| <a name="input_aviatrix_function_app_custom_role_name"></a> [aviatrix\_function\_app\_custom\_role\_name](#input\_aviatrix\_function\_app\_custom\_role\_name) | The name of the custom role to be created for the Aviatrix Function App to modify resources within the resource group. | `string` | `"aviatrix-function-custom-role"` | no |
| <a name="input_avx_access_account_name"></a> [avx\_access\_account\_name](#input\_avx\_access\_account\_name) | aviatrix controller access account name | `string` | n/a | yes |
| <a name="input_avx_account_email"></a> [avx\_account\_email](#input\_avx\_account\_email) | aviatrix controller access account email | `string` | n/a | yes |
| <a name="input_avx_aviatrix_customer_id"></a> [avx\_aviatrix\_customer\_id](#input\_avx\_aviatrix\_customer\_id) | aviatrix customer license id | `string` | n/a | yes |
| <a name="input_avx_controller_admin_email"></a> [avx\_controller\_admin\_email](#input\_avx\_controller\_admin\_email) | aviatrix controller admin email address | `string` | n/a | yes |
| <a name="input_avx_controller_admin_password"></a> [avx\_controller\_admin\_password](#input\_avx\_controller\_admin\_password) | aviatrix controller admin password | `string` | `""` | no |
| <a name="input_avx_controller_version"></a> [avx\_controller\_version](#input\_avx\_controller\_version) | Aviatrix Controller version | `string` | `"latest"` | no |
| <a name="input_az_support"></a> [az\_support](#input\_az\_support) | Set to true if the Azure region supports AZ's | `bool` | n/a | yes |
| <a name="input_controller_public_ssh_key"></a> [controller\_public\_ssh\_key](#input\_controller\_public\_ssh\_key) | Use a public SSH key for authentication to Aviatrix Controller | `string` | `""` | no |
| <a name="input_controller_virtual_machine_admin_password"></a> [controller\_virtual\_machine\_admin\_password](#input\_controller\_virtual\_machine\_admin\_password) | Admin Password for the controller virtual machine. | `string` | `""` | no |
| <a name="input_controller_virtual_machine_admin_username"></a> [controller\_virtual\_machine\_admin\_username](#input\_controller\_virtual\_machine\_admin\_username) | Admin Username for the controller virtual machine. | `string` | `"aviatrix"` | no |
| <a name="input_controller_virtual_machine_size"></a> [controller\_virtual\_machine\_size](#input\_controller\_virtual\_machine\_size) | Virtual Machine size for the controller. | `string` | `"Standard_A4_v2"` | no |
| <a name="input_create_custom_role"></a> [create\_custom\_role](#input\_create\_custom\_role) | Enable creation of custom role instead of using contributor permissions | `bool` | `false` | no |
| <a name="input_disable_periodic_backup"></a> [disable\_periodic\_backup](#input\_disable\_periodic\_backup) | This will disable Azure-Controller-Backup function created for periodic backups | `bool` | `true` | no |
| <a name="input_enable_function_app_alerts"></a> [enable\_function\_app\_alerts](#input\_enable\_function\_app\_alerts) | This will create the following Azure Monitor Alerts for the Function App; function triggered, function success, function failure, function exception. | `bool` | `false` | no |
| <a name="input_function_action_group_name"></a> [function\_action\_group\_name](#input\_function\_action\_group\_name) | The name of the action group created for alerting on the controller function app. (Triggers Function) | `string` | `"aviatrix-function-action-group"` | no |
| <a name="input_function_app_name"></a> [function\_app\_name](#input\_function\_app\_name) | The name of the function app to be deployed. | `string` | `""` | no |
| <a name="input_key_vault_name"></a> [key\_vault\_name](#input\_key\_vault\_name) | The key vault name that will be used to store credentials for the function app. | `string` | `""` | no |
| <a name="input_load_balancer_controller_backend_pool_name"></a> [load\_balancer\_controller\_backend\_pool\_name](#input\_load\_balancer\_controller\_backend\_pool\_name) | The Name of the Load Balancer backend pool for Aviatrix Controller. | `string` | `"aviatrix-controller-backend"` | no |
| <a name="input_load_balancer_controller_health_probe_name"></a> [load\_balancer\_controller\_health\_probe\_name](#input\_load\_balancer\_controller\_health\_probe\_name) | The Name of the Load Balancer Health Probe for Aviatrix Controller. | `string` | `"aviatrix-controller-probe"` | no |
| <a name="input_load_balancer_controller_rule_name"></a> [load\_balancer\_controller\_rule\_name](#input\_load\_balancer\_controller\_rule\_name) | The Name of the Load Balancer Rule for Aviatrix Controller. | `string` | `"aviatrix-controller-lb-rule"` | no |
| <a name="input_load_balancer_frontend_name"></a> [load\_balancer\_frontend\_name](#input\_load\_balancer\_frontend\_name) | The Name of the Load Balancer Frontend used for Load Balancer. | `string` | `"aviatrix-lb-frontend"` | no |
| <a name="input_load_balancer_frontend_public_ip_name"></a> [load\_balancer\_frontend\_public\_ip\_name](#input\_load\_balancer\_frontend\_public\_ip\_name) | The Name of the Public IP Address used for the Frontend of the Load Balancer | `string` | `"aviatrix-lb-public-ip"` | no |
| <a name="input_load_balancer_name"></a> [load\_balancer\_name](#input\_load\_balancer\_name) | The Name of the Load Balancer used for Aviatrix Devices. | `string` | `"aviatrix-lb"` | no |
| <a name="input_location"></a> [location](#input\_location) | Resource Group Location for Aviatrix Controller | `string` | n/a | yes |
| <a name="input_network_security_group_controller_name"></a> [network\_security\_group\_controller\_name](#input\_network\_security\_group\_controller\_name) | The Name of the Network Security Group for Aviatrix Controller. | `string` | `"aviatrix-controller-nsg"` | no |
| <a name="input_notification_action_group_id"></a> [notification\_action\_group\_id](#input\_notification\_action\_group\_id) | The Azure Resource ID for an existing action group; Use this for an already created action group instead of creating new one. | `string` | `""` | no |
| <a name="input_notification_action_group_name"></a> [notification\_action\_group\_name](#input\_notification\_action\_group\_name) | The name of the action group created for alerting notifications on the controller function app. (Email Only) | `string` | `"aviatrix-notify-action-group"` | no |
| <a name="input_resource_group_name"></a> [resource\_group\_name](#input\_resource\_group\_name) | The name of the resource group to be created. | `string` | n/a | yes |
| <a name="input_scale_set_controller_name"></a> [scale\_set\_controller\_name](#input\_scale\_set\_controller\_name) | The Name of the Scale Set used for the Aviatrix Controller. | `string` | `"aviatrix-controller-scale-set"` | no |
| <a name="input_schedule"></a> [schedule](#input\_schedule) | The cron timer syntax for periodic backup. | `string` | `"0 0 * * * *"` | no |
| <a name="input_storage_account_name"></a> [storage\_account\_name](#input\_storage\_account\_name) | The name of the storage account for the controller. | `string` | `""` | no |
| <a name="input_subnet_cidr"></a> [subnet\_cidr](#input\_subnet\_cidr) | Subnet Address Space used for Aviatrix Devices | `string` | `"10.0.0.0/24"` | no |
| <a name="input_subnet_name"></a> [subnet\_name](#input\_subnet\_name) | The name of the subnet used for Aviatrix Devices. | `string` | `"aviatrix-subnet"` | no |
| <a name="input_subscription_id"></a> [subscription\_id](#input\_subscription\_id) | subscription\_id | `string` | n/a | yes |
| <a name="input_to_be_created_service_principal_name"></a> [to\_be\_created\_service\_principal\_name](#input\_to\_be\_created\_service\_principal\_name) | Azure AD App Name for Aviatrix Controller Build Up | `string` | `"aviatrix_controller_app"` | no |
| <a name="input_user_assigned_identity_name"></a> [user\_assigned\_identity\_name](#input\_user\_assigned\_identity\_name) | The name of the user assigned identity created for the Controller Function App | `string` | `"aviatrix-function-identity"` | no |
| <a name="input_virtual_network_cidr"></a> [virtual\_network\_cidr](#input\_virtual\_network\_cidr) | Virtual Network Address Space used for Aviatrix Devices | `string` | `"10.0.0.0/23"` | no |
| <a name="input_virtual_network_name"></a> [virtual\_network\_name](#input\_virtual\_network\_name) | Virtual Network Name for Aviatrix Devices | `string` | `"aviatrix-vnet"` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_application_client_id"></a> [application\_client\_id](#output\_application\_client\_id) | The Application id of the Aviatrix Controller Application |
| <a name="output_avx_controller_lb_public_ip"></a> [avx\_controller\_lb\_public\_ip](#output\_avx\_controller\_lb\_public\_ip) | The Public IP Address of the Load Balancer |
| <a name="output_container_name"></a> [container\_name](#output\_container\_name) | The name of the container for the controller backup. |
| <a name="output_directory_id"></a> [directory\_id](#output\_directory\_id) | The Directory id of the Aviatrix Controller Application |
| <a name="output_key_vault_name"></a> [key\_vault\_name](#output\_key\_vault\_name) | The name of the key vault for controller secrets. |
| <a name="output_storage_name"></a> [storage\_name](#output\_storage\_name) | The name of the storage account for the controller. |
| <a name="output_subscription_id"></a> [subscription\_id](#output\_subscription\_id) | The subscription where the resources are deployed |
<!-- END_TF_DOCS -->