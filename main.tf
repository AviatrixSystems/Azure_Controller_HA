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
  source                                         = "./aviatrix_controller_ha"
  subscription_id                                = var.subscription_id # Required
  to_be_created_service_principal_name           = var.to_be_created_service_principal_name
  create_custom_role                             = var.create_custom_role
  resource_group_name                            = var.resource_group_name # Required
  location                                       = var.location            # Required
  storage_account_name                           = var.storage_account_name
  key_vault_name                                 = var.key_vault_name
  virtual_network_name                           = var.virtual_network_name
  virtual_network_cidr                           = var.virtual_network_cidr
  subnet_name                                    = var.subnet_name
  subnet_cidr                                    = var.subnet_cidr
  load_balancer_frontend_public_ip_name          = var.load_balancer_frontend_public_ip_name
  load_balancer_name                             = var.load_balancer_name
  load_balancer_frontend_name                    = var.load_balancer_frontend_name
  load_balancer_controller_backend_pool_name     = var.load_balancer_controller_backend_pool_name
  load_balancer_controller_health_probe_name     = var.load_balancer_controller_health_probe_name
  load_balancer_controller_rule_name             = var.load_balancer_controller_rule_name
  network_security_group_controller_name         = var.network_security_group_controller_name
  aviatrix_controller_security_group_allowed_ips = var.aviatrix_controller_security_group_allowed_ips
  controller_virtual_machine_size                = var.controller_virtual_machine_size
  scale_set_controller_name                      = var.scale_set_controller_name
  controller_virtual_machine_admin_username      = var.controller_virtual_machine_admin_username
  controller_virtual_machine_admin_password      = var.controller_virtual_machine_admin_password
  controller_public_ssh_key                      = var.controller_public_ssh_key
  avx_access_account_name                        = var.avx_access_account_name    # Required
  avx_account_email                              = var.avx_account_email          # Required
  avx_controller_admin_email                     = var.avx_controller_admin_email # Required
  avx_aviatrix_customer_id                       = var.avx_aviatrix_customer_id   # Required
  avx_controller_admin_password                  = var.avx_controller_admin_password
  avx_controller_version                         = var.avx_controller_version
  application_insights_name                      = var.application_insights_name
  app_service_plan_name                          = var.app_service_plan_name
  function_app_name                              = var.function_app_name
  user_assigned_identity_name                    = var.user_assigned_identity_name
  aviatrix_function_app_custom_role_name         = var.aviatrix_function_app_custom_role_name
  function_action_group_name                     = var.function_action_group_name
  notification_action_group_name                 = var.notification_action_group_name
  notification_action_group_id                   = var.notification_action_group_id
}
