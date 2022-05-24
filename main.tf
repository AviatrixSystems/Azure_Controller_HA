terraform {
  required_providers {
    azurerm = {
      source = "hashicorp/azurerm"
    }
    azuread = {
      source = "hashicorp/azuread"
    }
    null = {
      source = "hashicorp/null"
    }
  }
}

module "aviatrix_controller_azure" {
  source                                         = "./modules/aviatrix_controller_build"
  subscription_id                                = "d064bacd-49d6-4e0f-8d5b-7c62c50a686f" # Required
  to_be_created_service_principal_name           = "avis-ctrol-ha-sp"
  create_custom_role                             = false
  resource_group_name                            = "avis-ctrol-rg"    # Required
  location                                       = "South Central US" # Required
  storage_account_name                           = "aviscontrollertestsa"
  key_vault_name                                 = "avis-ctrol-kv"
  virtual_network_name                           = "avis-ctrol-vnet"
  virtual_network_cidr                           = "10.30.0.0/23"
  subnet_name                                    = "avis-ctrol-subnet"
  subnet_cidr                                    = "10.30.0.0/24"
  load_balancer_frontend_public_ip_name          = "avis-ctrol-public-ip"
  load_balancer_name                             = "avis-ctrol-lb"
  load_balancer_frontend_name                    = "aviatrix-lb-frontend"
  load_balancer_controller_backend_pool_name     = "aviatrix-controller-backend"
  load_balancer_controller_health_probe_name     = "aviatrix-controller-probe"
  load_balancer_controller_rule_name             = "aviatrix-controller-lb-rule"
  network_security_group_controller_name         = "aviatrix-controller-nsg"
  aviatrix_controller_security_group_allowed_ips = ["173.172.186.204", "49.206.57.225"]
  controller_virtual_machine_size                = "Standard_A4_v2"
  scale_set_controller_name                      = "avis-ctrol-scale-set"
  controller_virtual_machine_admin_username      = "adminUser"
  controller_virtual_machine_admin_password      = ""
  controller_public_ssh_key                      = ""
  avx_access_account_name                        = "avx-testing-account"      # Required
  avx_account_email                              = "pbomma@aviatrix.com"      # Required
  avx_controller_admin_email                     = "pbomma@aviatrix.com"      # Required
  avx_aviatrix_customer_id                       = "carmelodev-1393702544.64" # Required
  avx_controller_admin_password                  = ""
  avx_controller_version                         = "6.6"
  application_insights_name                      = "avis-ctrol-ai"
  app_service_plan_name                          = "avis-ctrol-app-service"
  function_app_name                              = "avis-ctrol-function-app"
  user_assigned_identity_name                    = "avis-ctrol-user-identity"
  aviatrix_function_app_custom_role_name         = "avis-ctrol-custom-role"
  function_action_group_name                     = "avis-function-ag"
  notification_action_group_name                 = "avis-notify-ag"
  notification_action_group_id                   = ""
}
