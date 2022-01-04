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

data "azurerm_subscription" "main" {}

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
  controller_virtual_machine_admin_password = var.controller_virtual_machine_admin_password
  controller_virtual_machine_size           = var.controller_virtual_machine_size
  incoming_ssl_cidr                         = var.incoming_ssl_cidr

  depends_on = [
    module.aviatrix_controller_arm
  ]
}

module "aviatrix_controller_initialize" {
  source                        = "./modules/aviatrix_controller_initialize"
  avx_controller_public_ip      = module.aviatrix_controller_build.aviatrix_controller_public_ip_address
  avx_controller_private_ip     = cidrhost(var.controller_subnet_cidr, 4)
  avx_controller_admin_email    = var.avx_controller_admin_email
  avx_controller_admin_password = var.avx_controller_admin_password
  arm_subscription_id           = module.aviatrix_controller_arm.subscription_id
  arm_application_id            = module.aviatrix_controller_arm.application_id
  arm_application_key           = module.aviatrix_controller_arm.application_key
  directory_id                  = module.aviatrix_controller_arm.directory_id
  account_email                 = var.account_email
  access_account_name           = var.access_account_name
  aviatrix_customer_id          = var.aviatrix_customer_id
  controller_version            = var.controller_version

  depends_on = [
    module.aviatrix_controller_arm
  ]
}

data "archive_file" "file_function_app" {
  type        = "zip"
  source_dir  = "./azure-controller"
  output_path = "azure-ha.zip"
}

resource "azurerm_storage_account" "aviatrix-controller-storage" {
  name                     = lower("${var.controller_name}${random_id.aviatrix.hex}")
  resource_group_name      = module.aviatrix_controller_build.aviatrix_controller_rg.name
  location                 = var.location
  account_tier             = "Standard"
  allow_blob_public_access = true
  account_replication_type = "LRS"
}

resource "azurerm_storage_container" "aviatrix-function-container" {
  name                  = lower("${var.controller_name}-ha")
  storage_account_name  = azurerm_storage_account.aviatrix-controller-storage.name
  container_access_type = "blob"
}

resource "azurerm_storage_container" "aviatrix-backup-container" {
  name                  = lower("${var.controller_name}-backup")
  storage_account_name  = azurerm_storage_account.aviatrix-controller-storage.name
  container_access_type = "blob"
}

resource "azurerm_storage_blob" "aviatrix-app" {
  name                   = "${filesha256(data.archive_file.file_function_app.output_path)}.zip"
  storage_account_name   = azurerm_storage_account.aviatrix-controller-storage.name
  storage_container_name = azurerm_storage_container.aviatrix-function-container.name
  type                   = "Block"
  source                 = data.archive_file.file_function_app.output_path
}

resource "azurerm_application_insights" "application_insights" {
  name                = "${var.controller_name}-function-application-insights"
  location            = var.location
  resource_group_name = module.aviatrix_controller_build.aviatrix_controller_rg.name
  application_type    = "web"
}

resource "azurerm_app_service_plan" "app_service_plan" {
  name                = "${var.controller_name}-app-service-plan"
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
  name                = azurerm_function_app.app.name
  resource_group_name = module.aviatrix_controller_build.aviatrix_controller_rg.name

  depends_on = [azurerm_function_app.app]
}

resource "azurerm_function_app" "app" {
  name                       = "${var.controller_name}-app-${random_id.aviatrix.hex}"
  location                   = var.location
  resource_group_name        = module.aviatrix_controller_build.aviatrix_controller_rg.name
  app_service_plan_id        = azurerm_app_service_plan.app_service_plan.id
  storage_account_name       = azurerm_storage_account.aviatrix-controller-storage.name
  storage_account_access_key = azurerm_storage_account.aviatrix-controller-storage.primary_access_key
  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.aviatrix_controller_identity.id]
  }
  os_type = "linux"
  version = "~4"

  app_settings = {
    "APPINSIGHTS_INSTRUMENTATIONKEY"  = azurerm_application_insights.application_insights.instrumentation_key,
    "func_client_id"                  = azurerm_user_assigned_identity.aviatrix_controller_identity.client_id,
    "avx_tenant_id"                   = module.aviatrix_controller_arm.directory_id,
    "avx_client_id"                   = module.aviatrix_controller_arm.application_id,
    "avx_secret_key"                  = module.aviatrix_controller_arm.application_key,
    "storage_name"                    = azurerm_storage_account.aviatrix-controller-storage.name,
    "container_name"                  = azurerm_storage_container.aviatrix-backup-container.name,
    "scaleset_name"                   = var.controller_name,
    "SCM_DO_BUILD_DURING_DEPLOYMENT"  = "true",
    "PYTHON_ENABLE_WORKER_EXTENSIONS" = "1"
    "ENABLE_ORYX_BUILD"               = "true",
    "FUNCTIONS_WORKER_RUNTIME"        = "python",
    "WEBSITE_RUN_FROM_PACKAGE"        = "https://${azurerm_storage_account.aviatrix-controller-storage.name}.blob.core.windows.net/${azurerm_storage_container.aviatrix-function-container.name}/${azurerm_storage_blob.aviatrix-app.name}"
  }

  site_config {
    linux_fx_version = "Python|3.9"
    ftps_state       = "Disabled"
  }
  depends_on = [
    module.aviatrix_controller_initialize
  ]
}

resource "azurerm_user_assigned_identity" "aviatrix_controller_identity" {
  resource_group_name = module.aviatrix_controller_build.aviatrix_controller_rg.name
  location            = var.location
  name                = "${var.controller_name}-function"
}

resource "azurerm_role_definition" "aviatrix_function_role" {
  name        = "${var.controller_name}-function-custom-role"
  scope       = module.aviatrix_controller_build.aviatrix_controller_rg.id
  description = "Custom role for Aviatrix Controller. Created via Terraform"

  permissions {
    actions = [
      "Microsoft.Compute/virtualMachines/*",
      "Microsoft.Compute/virtualMachineScaleSets/*",
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
  principal_id         = azurerm_user_assigned_identity.aviatrix_controller_identity.principal_id
}

resource "azurerm_role_assignment" "aviatrix_function_queue_role" {
  scope                = azurerm_storage_account.aviatrix-controller-storage.id
  role_definition_name = "Storage Queue Data Reader"
  principal_id         = azurerm_user_assigned_identity.aviatrix_controller_identity.principal_id
}

resource "azurerm_role_assignment" "aviatrix_custom_role" {
  scope                = module.aviatrix_controller_build.aviatrix_controller_rg.id
  role_definition_name = azurerm_role_definition.aviatrix_function_role.name
  principal_id         = azurerm_user_assigned_identity.aviatrix_controller_identity.principal_id
  depends_on = [
    azurerm_monitor_metric_alert.aviatrix_controller_alert
  ]
}


resource "azurerm_monitor_action_group" "aviatrix_controller_action" {
  enabled             = true
  name                = "${var.controller_name}-action"
  resource_group_name = module.aviatrix_controller_build.aviatrix_controller_rg.name
  short_name          = "avx-action"
  tags                = {}

  azure_function_receiver {
    function_app_resource_id = azurerm_function_app.app.id
    function_name            = azurerm_function_app.app.name
    http_trigger_url         = "https://${azurerm_function_app.app.default_hostname}/api/Azure-Controller-HA?code=${data.azurerm_function_app_host_keys.func_keys.default_function_key}"
    name                     = "func"
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
      name     = "BackendPort"
      operator = "Include"
      values = [
        "443",
      ]
    }
  }

}
