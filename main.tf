terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 2.0"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 1.0"
    }
    null = {
      source = "hashicorp/null"
    }
  }
}

resource "random_id" "aviatrix" {
  # Generate a new id each time we switch to a new funtion app
  byte_length = 4
}

resource "random_password" "generate_controller_secret" {
  length           = 24
  min_upper        = 2
  min_numeric      = 2
  min_special      = 2
  special          = true
  override_special = "_%@"
}

data "azurerm_subscription" "main" {}

data "azurerm_client_config" "current" {}

module "aviatrix_controller_arm" {
  source             = "./modules/aviatrix_controller_arm"
  app_name           = var.app_name
  create_custom_role = var.create_custom_role
}

module "aviatrix_controller_build" {
  source = "./modules/aviatrix_controller_build"
  // please do not use special characters such as `\/"[]:|<>+=;,?*@&~!#$%^()_{}'` in the controller_name
  controller_name                           = var.controller_name
  location                                  = var.location
  controller_vnet_cidr                      = var.controller_vnet_cidr
  controller_subnet_cidr                    = var.controller_subnet_cidr
  controller_virtual_machine_admin_username = var.controller_virtual_machine_admin_username
  controller_virtual_machine_admin_password = var.controller_virtual_machine_admin_password == "" ? random_password.generate_controller_secret.result : var.controller_virtual_machine_admin_password
  controller_virtual_machine_size           = var.controller_virtual_machine_size
  incoming_ssl_cidr                         = var.incoming_ssl_cidr
  copilot_name                              = var.copilot_name
  copilot_virtual_machine_admin_username    = var.copilot_virtual_machine_admin_username
  copilot_virtual_machine_admin_password    = var.copilot_virtual_machine_admin_password == "" ? random_password.generate_controller_secret.result : var.copilot_virtual_machine_admin_password
  copilot_virtual_machine_size              = var.copilot_virtual_machine_size
  copilot_additional_disks                  = var.copilot_additional_disks
  copilot_allowed_cidrs                     = var.copilot_allowed_cidrs
  depends_on = [
    module.aviatrix_controller_arm
  ]
}

module "aviatrix_controller_initialize" {
  source                        = "./modules/aviatrix_controller_initialize"
  avx_controller_public_ip      = module.aviatrix_controller_build.aviatrix_controller_lb_public_ip_address
  avx_controller_name           = var.controller_name
  avx_controller_admin_email    = var.avx_controller_admin_email
  avx_controller_admin_password = var.avx_controller_admin_password == "" ? random_password.generate_controller_secret.result : var.avx_controller_admin_password
  arm_subscription_id           = module.aviatrix_controller_arm.subscription_id
  arm_application_id            = module.aviatrix_controller_arm.application_id
  arm_application_key           = module.aviatrix_controller_arm.application_key
  directory_id                  = module.aviatrix_controller_arm.directory_id
  account_email                 = var.account_email
  access_account_name           = var.access_account_name
  aviatrix_customer_id          = var.aviatrix_customer_id
  controller_version            = var.controller_version
  resource_group_name           = module.aviatrix_controller_build.aviatrix_controller_rg.name

  depends_on = [
    module.aviatrix_controller_arm, module.aviatrix_controller_build
  ]
}


resource "azurerm_storage_account" "aviatrix-controller-storage" {
  name                     = lower("${var.controller_name}${random_id.aviatrix.hex}")
  resource_group_name      = module.aviatrix_controller_build.aviatrix_controller_rg.name
  location                 = var.location
  account_tier             = "Standard"
  allow_blob_public_access = true
  account_replication_type = "LRS"
}

resource "azurerm_storage_container" "aviatrix-backup-container" {
  name                  = lower("${var.controller_name}-backup")
  storage_account_name  = azurerm_storage_account.aviatrix-controller-storage.name
  container_access_type = "blob"
}

resource "azurerm_application_insights" "application_insights" {
  name                = "aviatrix-function-application-insights"
  location            = var.location
  resource_group_name = module.aviatrix_controller_build.aviatrix_controller_rg.name
  application_type    = "web"
}

resource "azurerm_app_service_plan" "controller_app_service_plan" {
  name                = "aviatrix-function-app-service-plan"
  resource_group_name = module.aviatrix_controller_build.aviatrix_controller_rg.name
  location            = var.location
  kind                = "elastic"
  reserved            = true
  sku {
    tier = "ElasticPremium"
    size = "EP1"
  }
}

data "azurerm_function_app_host_keys" "func_keys" {
  name                = azurerm_function_app.controller_app.name
  resource_group_name = module.aviatrix_controller_build.aviatrix_controller_rg.name

  depends_on = [azurerm_function_app.controller_app]
}

data "azurerm_function_app_host_keys" "copilot_func_keys" {
  name                = azurerm_function_app.copilot_app.name
  resource_group_name = module.aviatrix_controller_build.aviatrix_controller_rg.name

  depends_on = [azurerm_function_app.copilot_app]
}

resource "azurerm_function_app" "controller_app" {
  name                       = "${var.controller_name}-app-${random_id.aviatrix.hex}"
  location                   = var.location
  resource_group_name        = module.aviatrix_controller_build.aviatrix_controller_rg.name
  app_service_plan_id        = azurerm_app_service_plan.controller_app_service_plan.id
  storage_account_name       = azurerm_storage_account.aviatrix-controller-storage.name
  storage_account_access_key = azurerm_storage_account.aviatrix-controller-storage.primary_access_key
  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.aviatrix_identity.id]
  }
  os_type = "linux"
  version = "~4"

  app_settings = {
    "APPINSIGHTS_INSTRUMENTATIONKEY"  = azurerm_application_insights.application_insights.instrumentation_key,
    "func_client_id"                  = azurerm_user_assigned_identity.aviatrix_identity.client_id,
    "avx_tenant_id"                   = module.aviatrix_controller_arm.directory_id,
    "avx_client_id"                   = module.aviatrix_controller_arm.application_id,
    "keyvault_uri"                    = azurerm_key_vault.aviatrix_key_vault.vault_uri,
    "keyvault_secret"                 = azurerm_key_vault_secret.aviatrix_arm_secret.name,
    "storage_name"                    = azurerm_storage_account.aviatrix-controller-storage.name,
    "container_name"                  = azurerm_storage_container.aviatrix-backup-container.name,
    "scaleset_name"                   = var.controller_name,
    "SCM_DO_BUILD_DURING_DEPLOYMENT"  = "true",
    "PYTHON_ENABLE_WORKER_EXTENSIONS" = "1"
    "ENABLE_ORYX_BUILD"               = "true",
    "FUNCTIONS_WORKER_RUNTIME"        = "python",
  }

  site_config {
    linux_fx_version = "Python|3.9"
    ftps_state       = "Disabled"
  }
  depends_on = [
    module.aviatrix_controller_initialize,
    azurerm_key_vault_secret.aviatrix_arm_secret
  ]
}

resource "azurerm_function_app" "copilot_app" {
  name                       = "${var.copilot_name}-app-${random_id.aviatrix.hex}"
  location                   = var.location
  resource_group_name        = module.aviatrix_controller_build.aviatrix_controller_rg.name
  app_service_plan_id        = azurerm_app_service_plan.controller_app_service_plan.id
  storage_account_name       = azurerm_storage_account.aviatrix-controller-storage.name
  storage_account_access_key = azurerm_storage_account.aviatrix-controller-storage.primary_access_key
  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.aviatrix_identity.id]
  }
  os_type = "linux"
  version = "~4"

  app_settings = {
    "APPINSIGHTS_INSTRUMENTATIONKEY"  = azurerm_application_insights.application_insights.instrumentation_key,
    "func_client_id"                  = azurerm_user_assigned_identity.aviatrix_identity.client_id,
    "avx_tenant_id"                   = module.aviatrix_controller_arm.directory_id,
    "avx_client_id"                   = module.aviatrix_controller_arm.application_id,
    "copilot_scaleset_name"           = var.copilot_name,
    "SCM_DO_BUILD_DURING_DEPLOYMENT"  = "true",
    "PYTHON_ENABLE_WORKER_EXTENSIONS" = "1"
    "ENABLE_ORYX_BUILD"               = "true",
    "FUNCTIONS_WORKER_RUNTIME"        = "python",
  }

  site_config {
    linux_fx_version = "Python|3.9"
    ftps_state       = "Disabled"
  }
  depends_on = [
    module.aviatrix_controller_initialize,
    azurerm_key_vault_secret.aviatrix_arm_secret
  ]
}

resource "azurerm_user_assigned_identity" "aviatrix_identity" {
  resource_group_name = module.aviatrix_controller_build.aviatrix_controller_rg.name
  location            = var.location
  name                = "aviatrix-function-identity"
}

resource "azurerm_role_definition" "aviatrix_function_role" {
  name        = "${var.controller_name}-function-custom-role"
  scope       = module.aviatrix_controller_build.aviatrix_controller_rg.id
  description = "Custom role for Aviatrix Controller. Created via Terraform"

  permissions {
    actions = [
      "Microsoft.Compute/virtualMachines/*",
      "Microsoft.Compute/virtualMachineScaleSets/*",
      "Microsoft.Compute/disks/*",
      "Microsoft.Network/publicIPAddresses/*",
      "Microsoft.Network/networkInterfaces/*",
      "Microsoft.Network/networkSecurityGroups/*",
      "Microsoft.Network/loadBalancers/*",
      "Microsoft.Network/routeTables/*",
      "Microsoft.Network/virtualNetworks/*",
      "Microsoft.Network/networkSecurityGroups/*"
    ]
    not_actions = []
  }

  assignable_scopes = [
    module.aviatrix_controller_build.aviatrix_controller_rg.id,
  ]
}


resource "azurerm_role_assignment" "aviatrix_function_blob_role" {
  scope                = azurerm_storage_account.aviatrix-controller-storage.id
  role_definition_name = "Storage Blob Data Reader"
  principal_id         = azurerm_user_assigned_identity.aviatrix_identity.principal_id
}

resource "azurerm_role_assignment" "aviatrix_function_queue_role" {
  scope                = azurerm_storage_account.aviatrix-controller-storage.id
  role_definition_name = "Storage Queue Data Reader"
  principal_id         = azurerm_user_assigned_identity.aviatrix_identity.principal_id
}

resource "azurerm_role_assignment" "aviatrix_custom_role" {
  scope                = module.aviatrix_controller_build.aviatrix_controller_rg.id
  role_definition_name = azurerm_role_definition.aviatrix_function_role.name
  principal_id         = azurerm_user_assigned_identity.aviatrix_identity.principal_id
  depends_on = [
    azurerm_monitor_metric_alert.aviatrix_controller_alert
  ]
}

resource "azurerm_role_assignment" "aviatrix_function_vault_role" {
  scope                = azurerm_key_vault.aviatrix_key_vault.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.aviatrix_identity.principal_id
  depends_on           = [azurerm_role_assignment.key_vault_pipeline_service_principal]
}

resource "azurerm_monitor_action_group" "aviatrix_controller_action" {
  enabled             = true
  name                = "${var.controller_name}-action"
  resource_group_name = module.aviatrix_controller_build.aviatrix_controller_rg.name
  short_name          = "ctrl-action"
  tags                = {}

  azure_function_receiver {
    function_app_resource_id = azurerm_function_app.controller_app.id
    function_name            = azurerm_function_app.controller_app.name
    http_trigger_url         = "https://${azurerm_function_app.controller_app.default_hostname}/api/Azure-Controller-HA?code=${data.azurerm_function_app_host_keys.func_keys.default_function_key}"
    name                     = "controller-func"
    use_common_alert_schema  = false
  }

  email_receiver {
    email_address           = var.account_email
    name                    = "sendtoadmin"
    use_common_alert_schema = false
  }

}

resource "azurerm_monitor_action_group" "aviatrix_copilot_action" {
  enabled             = true
  name                = "${var.copilot_name}-action"
  resource_group_name = module.aviatrix_controller_build.aviatrix_controller_rg.name
  short_name          = "cplt-action"
  tags                = {}

  azure_function_receiver {
    function_app_resource_id = azurerm_function_app.controller_app.id
    function_name            = azurerm_function_app.copilot_app.name
    http_trigger_url         = "https://${azurerm_function_app.copilot_app.default_hostname}/api/Azure-Copilot-HA?code=${data.azurerm_function_app_host_keys.copilot_func_keys.default_function_key}"
    name                     = "copilot-func"
    use_common_alert_schema  = false
  }

  email_receiver {
    email_address           = var.account_email
    name                    = "sendtoadmin"
    use_common_alert_schema = false
  }

}
resource "azurerm_monitor_metric_alert" "aviatrix_controller_alert" {
  auto_mitigate       = true
  enabled             = true
  frequency           = "PT1M"
  name                = "${var.controller_name}-HealthCheck"
  resource_group_name = module.aviatrix_controller_build.aviatrix_controller_rg.name
  scopes = [
    module.aviatrix_controller_build.aviatrix_loadbalancer_id,
  ]
  severity             = 0
  tags                 = {}
  target_resource_type = "Microsoft.Network/loadBalancers"
  window_size          = "PT1M"

  action {
    action_group_id = azurerm_monitor_action_group.aviatrix_controller_action.id
  }

  criteria {
    aggregation            = "Maximum"
    metric_name            = "DipAvailability"
    metric_namespace       = "Microsoft.Network/loadBalancers"
    operator               = "LessThanOrEqual"
    skip_metric_validation = false
    threshold              = 0

    dimension {
      name     = "FrontendPort"
      operator = "Include"
      values = [
        "443",
      ]
    }
  }

}

resource "azurerm_monitor_metric_alert" "aviatrix_copilot_alert" {
  auto_mitigate       = true
  enabled             = true
  frequency           = "PT1M"
  name                = "${var.copilot_name}-HealthCheck"
  resource_group_name = module.aviatrix_controller_build.aviatrix_controller_rg.name
  scopes = [
    module.aviatrix_controller_build.aviatrix_loadbalancer_id,
  ]
  severity             = 0
  tags                 = {}
  target_resource_type = "Microsoft.Network/loadBalancers"
  window_size          = "PT1M"

  action {
    action_group_id = azurerm_monitor_action_group.aviatrix_copilot_action.id
  }

  criteria {
    aggregation            = "Maximum"
    metric_name            = "DipAvailability"
    metric_namespace       = "Microsoft.Network/loadBalancers"
    operator               = "LessThanOrEqual"
    skip_metric_validation = false
    threshold              = 0

    dimension {
      name     = "FrontendPort"
      operator = "Include"
      values = [
        "8443",
      ]
    }
  }
}

resource "azurerm_key_vault" "aviatrix_key_vault" {
  name                        = "${var.controller_name}-${random_id.aviatrix.hex}"
  resource_group_name         = module.aviatrix_controller_build.aviatrix_controller_rg.name
  location                    = var.location
  enabled_for_disk_encryption = true
  tenant_id                   = module.aviatrix_controller_arm.directory_id
  soft_delete_retention_days  = 7
  purge_protection_enabled    = false
  sku_name                    = "standard"
  enable_rbac_authorization   = true
}

resource "azurerm_role_assignment" "key_vault_pipeline_service_principal" {
  scope                = azurerm_key_vault.aviatrix_key_vault.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "azurerm_key_vault_secret" "aviatrix_arm_secret" {
  name         = "aviatrix-arm-key"
  value        = module.aviatrix_controller_arm.application_key
  key_vault_id = azurerm_key_vault.aviatrix_key_vault.id
  depends_on   = [azurerm_role_assignment.key_vault_pipeline_service_principal]
}

resource "azurerm_key_vault_secret" "controller_key_secret" {
  count        = var.avx_controller_admin_password != "" ? 0 : 1
  name         = "aviatrix-controller-key"
  value        = random_password.generate_controller_secret.result
  key_vault_id = azurerm_key_vault.aviatrix_key_vault.id
  depends_on   = [azurerm_role_assignment.key_vault_pipeline_service_principal]
}

resource "null_resource" "run_controller_function" {
  provisioner "local-exec" {
    command = "cd azure-controller && func azure functionapp publish ${var.controller_name}-app-${random_id.aviatrix.hex}"
  }
  depends_on = [time_sleep.controller_function_provision]
}

resource "null_resource" "run_copilot_function" {
  provisioner "local-exec" {
    command = "cd azure-copilot && func azure functionapp publish ${var.copilot_name}-app-${random_id.aviatrix.hex}"
  }
  depends_on = [time_sleep.copilot_function_provision]
}

resource "time_sleep" "controller_function_provision" {
  create_duration = "30s"

  triggers = {
    function_id = azurerm_function_app.controller_app.name
  }
}

resource "time_sleep" "copilot_function_provision" {
  create_duration = "30s"

  triggers = {
    function_id = azurerm_function_app.copilot_app.name
  }
}
