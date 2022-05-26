<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_azuread"></a> [azuread](#requirement\_azuread) | ~> 2.0 |
| <a name="requirement_azurerm"></a> [azurerm](#requirement\_azurerm) | ~> 2.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_azurerm"></a> [azurerm](#provider\_azurerm) | ~> 2.0 |
| <a name="provider_null"></a> [null](#provider\_null) | n/a |
| <a name="provider_random"></a> [random](#provider\_random) | n/a |
| <a name="provider_time"></a> [time](#provider\_time) | n/a |

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_aviatrix_controller_arm"></a> [aviatrix\_controller\_arm](#module\_aviatrix\_controller\_arm) | github.com/AviatrixSystems/terraform-aviatrix-azure-controller//modules/aviatrix_controller_azure | v2.0.0 |
| <a name="module_aviatrix_controller_initialize"></a> [aviatrix\_controller\_initialize](#module\_aviatrix\_controller\_initialize) | github.com/AviatrixSystems/terraform-aviatrix-azure-controller//modules/aviatrix_controller_initialize | v2.0.0 |

## Resources

| Name | Type |
|------|------|
| [azurerm_app_service_plan.controller_app_service_plan](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service_plan) | resource |
| [azurerm_application_insights.application_insights](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/application_insights) | resource |
| [azurerm_function_app.controller_app](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/function_app) | resource |
| [azurerm_key_vault.aviatrix_key_vault](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault) | resource |
| [azurerm_key_vault_secret.aviatrix_arm_secret](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_secret) | resource |
| [azurerm_key_vault_secret.controller_key_secret](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_secret) | resource |
| [azurerm_lb.aviatrix_lb](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/lb) | resource |
| [azurerm_lb_backend_address_pool.aviatrix_controller_lb_backend_pool](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/lb_backend_address_pool) | resource |
| [azurerm_lb_probe.aviatrix_controller_lb_probe](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/lb_probe) | resource |
| [azurerm_lb_rule.aviatrix_controller_lb_rule](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/lb_rule) | resource |
| [azurerm_monitor_action_group.aviatrix_controller_action](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_action_group) | resource |
| [azurerm_monitor_action_group.aviatrix_notification_action_group](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_action_group) | resource |
| [azurerm_monitor_metric_alert.aviatrix_controller_alert](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_metric_alert) | resource |
| [azurerm_monitor_metric_alert.function_app_exception_alert](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_metric_alert) | resource |
| [azurerm_monitor_metric_alert.function_app_failed_alert](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_metric_alert) | resource |
| [azurerm_monitor_metric_alert.function_app_success_alert](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_metric_alert) | resource |
| [azurerm_network_security_group.aviatrix_controller_nsg](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_security_group) | resource |
| [azurerm_network_security_rule.function_app_rules](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_security_rule) | resource |
| [azurerm_network_security_rule.user_defined_rules](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_security_rule) | resource |
| [azurerm_orchestrated_virtual_machine_scale_set.aviatrix_scale_set](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/orchestrated_virtual_machine_scale_set) | resource |
| [azurerm_public_ip.aviatrix_lb_public_ip](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/public_ip) | resource |
| [azurerm_resource_group.aviatrix_rg](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/resource_group) | resource |
| [azurerm_role_assignment.aviatrix_custom_role](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/role_assignment) | resource |
| [azurerm_role_assignment.aviatrix_function_blob_role](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/role_assignment) | resource |
| [azurerm_role_assignment.aviatrix_function_queue_role](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/role_assignment) | resource |
| [azurerm_role_assignment.aviatrix_function_vault_role](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/role_assignment) | resource |
| [azurerm_role_assignment.key_vault_pipeline_service_principal](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/role_assignment) | resource |
| [azurerm_role_definition.aviatrix_function_role](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/role_definition) | resource |
| [azurerm_storage_account.aviatrix_controller_storage](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account) | resource |
| [azurerm_storage_container.aviatrix_backup_container](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_container) | resource |
| [azurerm_subnet.aviatrix_controller_subnet](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/subnet) | resource |
| [azurerm_user_assigned_identity.aviatrix_identity](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/user_assigned_identity) | resource |
| [azurerm_virtual_network.aviatrix_vnet](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_network) | resource |
| [null_resource.run_controller_function](https://registry.terraform.io/providers/hashicorp/null/latest/docs/resources/resource) | resource |
| [random_id.aviatrix](https://registry.terraform.io/providers/hashicorp/random/latest/docs/resources/id) | resource |
| [random_password.generate_controller_secret](https://registry.terraform.io/providers/hashicorp/random/latest/docs/resources/password) | resource |
| [time_sleep.controller_function_provision](https://registry.terraform.io/providers/hashicorp/time/latest/docs/resources/sleep) | resource |
| [time_sleep.sleep_1m_user_identity](https://registry.terraform.io/providers/hashicorp/time/latest/docs/resources/sleep) | resource |
| [azurerm_client_config.current](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/data-sources/client_config) | data source |
| [azurerm_function_app_host_keys.func_keys](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/data-sources/function_app_host_keys) | data source |
| [azurerm_resources.get_vmss_instance](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/data-sources/resources) | data source |
| [azurerm_virtual_machine.vm_data](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/data-sources/virtual_machine) | data source |

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
| <a name="output_avx_controller_lb_public_ip"></a> [avx\_controller\_lb\_public\_ip](#output\_avx\_controller\_lb\_public\_ip) | The Public IP Address of the Load Balancer |
<!-- END_TF_DOCS -->