variable "subscription_id" {
  type        = string
  description = "subscription_id"
}

variable "to_be_created_service_principal_name" {
  type        = string
  description = "Azure AD App Name for Aviatrix Controller Build Up"
  default     = "aviatrix_controller_app"
}

variable "create_custom_role" {
  type        = bool
  description = "Enable creation of custom role instead of using contributor permissions"
  default     = false
}

variable "resource_group_name" {
  type        = string
  description = "The name of the resource group to be created."
}

variable "location" {
  type        = string
  description = "Resource Group Location for Aviatrix Controller"
}

variable "storage_account_name" {
  type        = string
  description = "The name of the storage account for the controller."
  default     = ""
}

variable "key_vault_name" {
  type        = string
  description = "The key vault name that will be used to store credentials for the function app."
  default     = ""
}

variable "virtual_network_name" {
  type        = string
  description = "Virtual Network Name for Aviatrix Devices"
  default     = "aviatrix-vnet"
}

variable "virtual_network_cidr" {
  type        = string
  description = "Virtual Network Address Space used for Aviatrix Devices"
  default     = "10.0.0.0/23"
}

variable "subnet_name" {
  type        = string
  description = "The name of the subnet used for Aviatrix Devices."
  default     = "aviatrix-subnet"
}

variable "subnet_cidr" {
  type        = string
  description = "Subnet Address Space used for Aviatrix Devices"
  default     = "10.0.0.0/24"
}

variable "load_balancer_frontend_public_ip_name" {
  type        = string
  description = "The Name of the Public IP Address used for the Frontend of the Load Balancer"
  default     = "aviatrix-lb-public-ip"
}

variable "load_balancer_name" {
  type        = string
  description = "The Name of the Load Balancer used for Aviatrix Devices."
  default     = "aviatrix-lb"
}

variable "load_balancer_frontend_name" {
  type        = string
  description = "The Name of the Load Balancer Frontend used for Load Balancer."
  default     = "aviatrix-lb-frontend"
}

variable "load_balancer_controller_backend_pool_name" {
  type        = string
  description = "The Name of the Load Balancer backend pool for Aviatrix Controller."
  default     = "aviatrix-controller-backend"
}

variable "load_balancer_controller_health_probe_name" {
  type        = string
  description = "The Name of the Load Balancer Health Probe for Aviatrix Controller."
  default     = "aviatrix-controller-probe"
}

variable "load_balancer_controller_rule_name" {
  type        = string
  description = "The Name of the Load Balancer Rule for Aviatrix Controller."
  default     = "aviatrix-controller-lb-rule"
}

variable "network_security_group_controller_name" {
  type        = string
  description = "The Name of the Network Security Group for Aviatrix Controller."
  default     = "aviatrix-controller-nsg"
}

variable "aviatrix_controller_security_group_allowed_ips" {
  type        = list(string)
  description = "Incoming cidr for security group used by controller"
}

variable "controller_virtual_machine_size" {
  type        = string
  description = "Virtual Machine size for the controller."
  default     = "Standard_A4_v2"
}

variable "scale_set_controller_name" {
  type        = string
  description = "The Name of the Scale Set used for the Aviatrix Controller."
  default     = "aviatrix-controller-scale-set"
}

variable "controller_virtual_machine_admin_username" {
  type        = string
  description = "Admin Username for the controller virtual machine."
  default     = "aviatrix"
}

variable "controller_virtual_machine_admin_password" {
  type        = string
  description = "Admin Password for the controller virtual machine."
  default     = ""
  sensitive   = true
}

variable "controller_public_ssh_key" {
  type        = string
  description = "Use a public SSH key for authentication to Aviatrix Controller"
  default     = ""
}

variable "avx_access_account_name" {
  type        = string
  description = "aviatrix controller access account name"
}

variable "avx_account_email" {
  type        = string
  description = "aviatrix controller access account email"
}

variable "avx_controller_admin_email" {
  type        = string
  description = "aviatrix controller admin email address"
}

variable "avx_aviatrix_customer_id" {
  type        = string
  description = "aviatrix customer license id"
}

variable "avx_controller_admin_password" {
  type        = string
  description = "aviatrix controller admin password"
  default     = ""
  sensitive   = true
}

variable "avx_controller_version" {
  type        = string
  description = "Aviatrix Controller version"
  default     = "latest"
}

variable "application_insights_name" {
  type        = string
  description = "The name of the application insights to be deployed for the function app."
  default     = "aviatrix-function-app-insights"
}

variable "app_service_plan_name" {
  type        = string
  description = "The name of the app service plan to be deployed."
  default     = "aviatrix-function-app-sp"
}

variable "function_app_name" {
  type        = string
  description = "The name of the function app to be deployed."
  default     = ""
}

variable "user_assigned_identity_name" {
  type        = string
  description = "The name of the user assigned identity created for the Controller Function App"
  default     = "aviatrix-function-identity"
}

variable "aviatrix_function_app_custom_role_name" {
  type        = string
  description = "The name of the custom role to be created for the Aviatrix Function App to modify resources within the resource group."
  default     = "aviatrix-function-custom-role"
}

variable "function_action_group_name" {
  type        = string
  description = "The name of the action group created for alerting on the controller function app. (Triggers Function)"
  default     = "aviatrix-function-action-group"
}

variable "enable_function_app_alerts" {
  type        = bool
  description = "This will create the following Azure Monitor Alerts for the Function App; function triggered, function success, function failure, function exception."
  default     = false
}

variable "notification_action_group_name" {
  type        = string
  description = "The name of the action group created for alerting notifications on the controller function app. (Email Only)"
  default     = "aviatrix-notify-action-group"
}

variable "notification_action_group_id" {
  type        = string
  description = "The Azure Resource ID for an existing action group; Use this for an already created action group instead of creating new one."
  default     = ""
}

