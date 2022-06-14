terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 2.0"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.0"
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
  count            = var.avx_controller_admin_password == "" ? 1 : 0
  length           = 24
  min_upper        = 2
  min_numeric      = 2
  min_special      = 2
  special          = true
  override_special = "_%@"
}

resource "random_password" "generate_controller_cli_secret" {
  count            = var.controller_virtual_machine_admin_password == "" ? 1 : 0
  length           = 24
  min_upper        = 2
  min_numeric      = 2
  min_special      = 2
  special          = true
  override_special = "_%@"
}

data "azurerm_client_config" "current" {}

# 1.0. Create Custom Service Principal for Aviatrix Controller
module "aviatrix_controller_arm" {
  source             = "github.com/AviatrixSystems/terraform-aviatrix-azure-controller//modules/aviatrix_controller_azure?ref=v2.0.0"
  app_name           = var.to_be_created_service_principal_name
  create_custom_role = var.create_custom_role
}

# 2.0. Create the Resource Group
resource "azurerm_resource_group" "aviatrix_rg" {
  name     = var.resource_group_name
  location = var.location
}

# 3.0. Create Storage Account
resource "azurerm_storage_account" "aviatrix_controller_storage" {
  #checkov:skip=CKV_AZURE_59:This storage account requires public access
  name                      = var.storage_account_name == "" ? "aviatrixstorage${random_id.aviatrix.hex}" : var.storage_account_name
  resource_group_name       = azurerm_resource_group.aviatrix_rg.name
  location                  = azurerm_resource_group.aviatrix_rg.location
  account_tier              = "Standard"
  allow_blob_public_access  = true
  account_replication_type  = "LRS"
  min_tls_version           = "TLS1_2"
  enable_https_traffic_only = true
}

# 3.1. Create Storage Container
resource "azurerm_storage_container" "aviatrix_backup_container" {
  name                  = lower("${var.scale_set_controller_name}-backup")
  storage_account_name  = azurerm_storage_account.aviatrix_controller_storage.name
  container_access_type = "private"
}

# 4.0. Create Key Vault
resource "azurerm_key_vault" "aviatrix_key_vault" {
  #checkov:skip=CKV_AZURE_109:This key vault cannot be locked down.
  name                        = var.key_vault_name == "" ? "aviatrix-kv-${random_id.aviatrix.hex}" : var.key_vault_name
  resource_group_name         = azurerm_resource_group.aviatrix_rg.name
  location                    = azurerm_resource_group.aviatrix_rg.location
  enabled_for_disk_encryption = true
  tenant_id                   = module.aviatrix_controller_arm.directory_id
  soft_delete_retention_days  = 7
  purge_protection_enabled    = false
  sku_name                    = "standard"
  enable_rbac_authorization   = true
}

# 4.1. Allow Current Object ID to add Secrets to Key Vault
resource "azurerm_role_assignment" "key_vault_pipeline_service_principal" {
  scope                = azurerm_key_vault.aviatrix_key_vault.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

# 4.2. Add Service Principal Secret to Key Vault
resource "azurerm_key_vault_secret" "aviatrix_arm_secret" {
  depends_on = [
    azurerm_role_assignment.key_vault_pipeline_service_principal
  ]
  name         = "aviatrix-arm-key"
  value        = module.aviatrix_controller_arm.application_key
  key_vault_id = azurerm_key_vault.aviatrix_key_vault.id
  content_type = "Controller Service Principal Key"
}

# 4.3. Add Controller Password to Key Vault
resource "azurerm_key_vault_secret" "controller_key_secret" {
  depends_on = [
    azurerm_role_assignment.key_vault_pipeline_service_principal
  ]
  name         = "aviatrix-controller-key"
  value        = var.avx_controller_admin_password == "" ? random_password.generate_controller_secret[0].result : var.avx_controller_admin_password
  key_vault_id = azurerm_key_vault.aviatrix_key_vault.id
  content_type = "Aviatrix Controller Admin Password"
}

# 4.4. Add Controller Virtual Machine CLI Password to Key Vault
resource "azurerm_key_vault_secret" "controller_vm_cli_key_secret" {
  depends_on = [
    azurerm_role_assignment.key_vault_pipeline_service_principal
  ]
  name         = "aviatrix-controller-vm-cli-key"
  value        = var.controller_virtual_machine_admin_password == "" ? random_password.generate_controller_cli_secret[0].result : var.controller_virtual_machine_admin_password
  key_vault_id = azurerm_key_vault.aviatrix_key_vault.id
  content_type = "Aviatrix Controller VM CLI Admin Password"
}

# 5.0. Create Virtual Network
resource "azurerm_virtual_network" "aviatrix_vnet" {
  name                = var.virtual_network_name
  resource_group_name = azurerm_resource_group.aviatrix_rg.name
  location            = azurerm_resource_group.aviatrix_rg.location
  address_space       = [var.virtual_network_cidr]
}

# 5.1. Create Controller Subnet
resource "azurerm_subnet" "aviatrix_controller_subnet" {
  name                 = var.subnet_name
  resource_group_name  = azurerm_resource_group.aviatrix_rg.name
  virtual_network_name = azurerm_virtual_network.aviatrix_vnet.name
  address_prefixes     = [var.subnet_cidr]
}

# 6.0. Create Public IP Address for LB
resource "azurerm_public_ip" "aviatrix_lb_public_ip" {
  name                = var.load_balancer_frontend_public_ip_name
  resource_group_name = azurerm_resource_group.aviatrix_rg.name
  location            = azurerm_resource_group.aviatrix_rg.location
  allocation_method   = "Static"
  sku                 = "Standard"
  availability_zone   = var.az_support ? "Zone-Redundant" : "No-Zone"
}

# 6.1. Create load balancer
resource "azurerm_lb" "aviatrix_lb" {
  name                = var.load_balancer_name
  resource_group_name = azurerm_resource_group.aviatrix_rg.name
  location            = azurerm_resource_group.aviatrix_rg.location
  sku                 = "Standard"
  sku_tier            = "Regional"
  tags                = {}

  frontend_ip_configuration {
    name                          = var.load_balancer_frontend_name
    availability_zone             = "No-Zone"
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.aviatrix_lb_public_ip.id
  }
}

# 6.2. Create Controller load balancer backend pool
resource "azurerm_lb_backend_address_pool" "aviatrix_controller_lb_backend_pool" {
  loadbalancer_id = azurerm_lb.aviatrix_lb.id
  name            = var.load_balancer_controller_backend_pool_name
}

# 6.3. Create Controller load balancer health probe
resource "azurerm_lb_probe" "aviatrix_controller_lb_probe" {
  name                = var.load_balancer_controller_health_probe_name
  resource_group_name = azurerm_resource_group.aviatrix_rg.name
  loadbalancer_id     = azurerm_lb.aviatrix_lb.id
  interval_in_seconds = 5
  number_of_probes    = 2
  port                = 443
  protocol            = "TCP"
}

# 6.4. Create Controller load balancer rule
resource "azurerm_lb_rule" "aviatrix_controller_lb_rule" {
  name                           = var.load_balancer_controller_rule_name
  resource_group_name            = azurerm_resource_group.aviatrix_rg.name
  loadbalancer_id                = azurerm_lb.aviatrix_lb.id
  frontend_ip_configuration_name = azurerm_lb.aviatrix_lb.frontend_ip_configuration[0].name
  probe_id                       = azurerm_lb_probe.aviatrix_controller_lb_probe.id
  backend_address_pool_ids       = [azurerm_lb_backend_address_pool.aviatrix_controller_lb_backend_pool.id]
  frontend_port                  = 443
  backend_port                   = 443
  idle_timeout_in_minutes        = 4
  protocol                       = "TCP"
  disable_outbound_snat          = true
  enable_floating_ip             = false
  enable_tcp_reset               = false
}

# 7.0. Create the Controller Security Group
resource "azurerm_network_security_group" "aviatrix_controller_nsg" {
  name                = var.network_security_group_controller_name
  resource_group_name = azurerm_resource_group.aviatrix_rg.name
  location            = azurerm_resource_group.aviatrix_rg.location
}

# 7.1. Create Rule For Allowed HTTPS Inbound IP Addresses
resource "azurerm_network_security_rule" "user_defined_rules" {
  name                        = "httpsInboundToScaleSet"
  resource_group_name         = azurerm_resource_group.aviatrix_rg.name
  network_security_group_name = azurerm_network_security_group.aviatrix_controller_nsg.name
  access                      = "Allow"
  direction                   = "Inbound"
  priority                    = "200"
  protocol                    = "TCP"
  source_port_range           = "*"
  destination_port_range      = "443"
  source_address_prefixes     = var.aviatrix_controller_security_group_allowed_ips
  destination_address_prefix  = "*"
  description                 = "httpsInboundToControllerScaleSet"
}

# 8.0 Deploy Aviatrix Controller Scale Set
resource "azurerm_orchestrated_virtual_machine_scale_set" "aviatrix_scale_set" {
  name                        = var.scale_set_controller_name
  resource_group_name         = azurerm_resource_group.aviatrix_rg.name
  location                    = azurerm_resource_group.aviatrix_rg.location
  sku_name                    = var.controller_virtual_machine_size
  priority                    = "Regular"
  instances                   = 1
  platform_fault_domain_count = 1
  encryption_at_host_enabled  = false
  zone_balance                = false
  tags = {
    "aviatrix_image" = "aviatrix-controller"
  }

  automatic_instance_repair {
    enabled = false
  }

  network_interface {
    dns_servers                   = []
    enable_accelerated_networking = false
    enable_ip_forwarding          = false
    name                          = "${var.scale_set_controller_name}-nic01"
    network_security_group_id     = azurerm_network_security_group.aviatrix_controller_nsg.id
    primary                       = true

    ip_configuration {
      load_balancer_backend_address_pool_ids = [
        azurerm_lb_backend_address_pool.aviatrix_controller_lb_backend_pool.id
      ]
      name      = "${var.scale_set_controller_name}-nic01"
      primary   = true
      subnet_id = azurerm_subnet.aviatrix_controller_subnet.id
      version   = "IPv4"

      public_ip_address {
        idle_timeout_in_minutes = 15
        name                    = "${var.scale_set_controller_name}-public-ip"
      }
    }
  }

  os_profile {
    linux_configuration {
      computer_name_prefix            = "aviatrix-"
      disable_password_authentication = var.controller_public_ssh_key == "" ? false : true
      admin_username                  = var.controller_virtual_machine_admin_username
      admin_password                  = length(var.controller_public_ssh_key) > 0 ? null : var.controller_virtual_machine_admin_password == "" ? random_password.generate_controller_cli_secret[0].result : var.controller_virtual_machine_admin_password
      provision_vm_agent              = true
      dynamic "admin_ssh_key" {
        for_each = var.controller_public_ssh_key == "" ? [] : [true]
        content {
          public_key = var.controller_public_ssh_key
          username   = var.controller_virtual_machine_admin_username
        }
      }
    }
  }

  plan {
    name      = "aviatrix-enterprise-bundle-byol"
    product   = "aviatrix-bundle-payg"
    publisher = "aviatrix-systems"
  }

  source_image_reference {
    offer     = "aviatrix-bundle-payg"
    publisher = "aviatrix-systems"
    sku       = "aviatrix-enterprise-bundle-byol"
    version   = "latest"
  }

  os_disk {
    caching                   = "ReadWrite"
    disk_size_gb              = 30
    storage_account_type      = "Standard_LRS"
    write_accelerator_enabled = false
  }
}

# 8.1. Get VMSS Instance by Tag
data "azurerm_resources" "get_vmss_instance" {
  depends_on = [
    azurerm_orchestrated_virtual_machine_scale_set.aviatrix_scale_set
  ]
  resource_group_name = azurerm_resource_group.aviatrix_rg.name
  type                = "Microsoft.Compute/virtualMachines"

  required_tags = {
    aviatrix_image = "aviatrix-controller"
  }
}

# 8.2. Get Private IP of VMSS Controller Instance
data "azurerm_virtual_machine" "vm_data" {
  name                = data.azurerm_resources.get_vmss_instance.resources[0].name
  resource_group_name = azurerm_resource_group.aviatrix_rg.name
}

# 9.0. Initial Controller Configurations (occurs only on first deployment)
module "aviatrix_controller_initialize" {
  source                        = "github.com/AviatrixSystems/terraform-aviatrix-azure-controller//modules/aviatrix_controller_initialize?ref=v2.0.0"
  avx_controller_public_ip      = azurerm_public_ip.aviatrix_lb_public_ip.ip_address
  avx_controller_private_ip     = data.azurerm_virtual_machine.vm_data.private_ip_address
  avx_controller_admin_email    = var.avx_controller_admin_email
  avx_controller_admin_password = var.avx_controller_admin_password == "" ? random_password.generate_controller_secret[0].result : var.avx_controller_admin_password
  arm_subscription_id           = module.aviatrix_controller_arm.subscription_id
  arm_application_id            = module.aviatrix_controller_arm.application_id
  arm_application_key           = module.aviatrix_controller_arm.application_key
  directory_id                  = module.aviatrix_controller_arm.directory_id
  account_email                 = var.avx_account_email
  access_account_name           = var.avx_access_account_name
  aviatrix_customer_id          = var.avx_aviatrix_customer_id
  controller_version            = var.avx_controller_version
}

### RBAC For Function App ###

# 10.0. Create Custom Role Definition for Function App
resource "azurerm_role_definition" "aviatrix_function_role" {
  name        = format("%s-%s", var.aviatrix_function_app_custom_role_name, "${random_id.aviatrix.hex}")
  scope       = azurerm_resource_group.aviatrix_rg.id
  description = "Custom role for Aviatrix Controller Function App. Created via Terraform"

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
    azurerm_resource_group.aviatrix_rg.id
  ]
}

# 10.1. Create User Assigned Identity for Function App
resource "azurerm_user_assigned_identity" "aviatrix_identity" {
  name                = var.user_assigned_identity_name
  resource_group_name = azurerm_resource_group.aviatrix_rg.name
  location            = azurerm_resource_group.aviatrix_rg.location
}

# 10.2. Sleep 1 Minute Before Assigning Role to User Identity
resource "time_sleep" "sleep_1m_user_identity" {
  create_duration = "1m"

  triggers = {
    function_id = azurerm_user_assigned_identity.aviatrix_identity.principal_id
  }
}

# 10.3. Assign User Identity to Custom Role
resource "azurerm_role_assignment" "aviatrix_custom_role" {
  depends_on = [
    time_sleep.sleep_1m_user_identity,
    azurerm_role_definition.aviatrix_function_role,
    azurerm_user_assigned_identity.aviatrix_identity
  ]
  scope              = azurerm_resource_group.aviatrix_rg.id
  role_definition_id = azurerm_role_definition.aviatrix_function_role.role_definition_resource_id
  principal_id       = azurerm_user_assigned_identity.aviatrix_identity.principal_id
}

# 10.4. Assign User Identity to Storage Blob Reader Role
resource "azurerm_role_assignment" "aviatrix_function_blob_role" {
  scope                = azurerm_storage_account.aviatrix_controller_storage.id
  role_definition_name = "Storage Blob Data Reader"
  principal_id         = azurerm_user_assigned_identity.aviatrix_identity.principal_id
}

# 10.5. Assign User Identity to Storage Queue Role
resource "azurerm_role_assignment" "aviatrix_function_queue_role" {
  scope                = azurerm_storage_account.aviatrix_controller_storage.id
  role_definition_name = "Storage Queue Data Reader"
  principal_id         = azurerm_user_assigned_identity.aviatrix_identity.principal_id
}

# 10.6. Assign User Identity to Key Vault Secrets User Role
resource "azurerm_role_assignment" "aviatrix_function_vault_role" {
  depends_on = [
    azurerm_role_assignment.key_vault_pipeline_service_principal
  ]
  scope                = azurerm_key_vault.aviatrix_key_vault.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.aviatrix_identity.principal_id
}

# 11.0. Deploy Application Insights
resource "azurerm_application_insights" "application_insights" {
  name                = var.application_insights_name
  location            = azurerm_resource_group.aviatrix_rg.location
  resource_group_name = azurerm_resource_group.aviatrix_rg.name
  application_type    = "web"
}

# 11.1. Deploy App Service Plan
resource "azurerm_app_service_plan" "controller_app_service_plan" {
  name                = var.app_service_plan_name
  resource_group_name = azurerm_resource_group.aviatrix_rg.name
  location            = azurerm_resource_group.aviatrix_rg.location
  kind                = "elastic"
  reserved            = true

  sku {
    tier = "ElasticPremium"
    size = "EP1"
  }
}

# 11.2. Deploy Controller Function App
resource "azurerm_function_app" "controller_app" {
  name                       = var.function_app_name == "" ? "aviatrix-controller-app-${random_id.aviatrix.hex}" : var.function_app_name
  resource_group_name        = azurerm_resource_group.aviatrix_rg.name
  location                   = azurerm_resource_group.aviatrix_rg.location
  app_service_plan_id        = azurerm_app_service_plan.controller_app_service_plan.id
  storage_account_name       = azurerm_storage_account.aviatrix_controller_storage.name
  storage_account_access_key = azurerm_storage_account.aviatrix_controller_storage.primary_access_key
  os_type                    = "linux"
  version                    = "~4"
  https_only                 = true

  auth_settings {
    enabled                       = true
    unauthenticated_client_action = "AllowAnonymous"
  }
  
  identity {
    type = "UserAssigned"
    identity_ids = [
      azurerm_user_assigned_identity.aviatrix_identity.id
    ]
  }

  app_settings = {
    "APPINSIGHTS_INSTRUMENTATIONKEY"  = azurerm_application_insights.application_insights.instrumentation_key,
    "BUILD_FLAGS"                     = "UseExpressBuild",
    "XDG_CACHE_HOME"                  = "/tmp/.cache",
    "func_client_id"                  = azurerm_user_assigned_identity.aviatrix_identity.client_id,
    "avx_tenant_id"                   = module.aviatrix_controller_arm.directory_id,
    "avx_client_id"                   = module.aviatrix_controller_arm.application_id,
    "keyvault_uri"                    = azurerm_key_vault.aviatrix_key_vault.vault_uri,
    "keyvault_secret"                 = azurerm_key_vault_secret.aviatrix_arm_secret.name,
    "storage_name"                    = azurerm_storage_account.aviatrix_controller_storage.name,
    "container_name"                  = azurerm_storage_container.aviatrix_backup_container.name,
    "scaleset_name"                   = azurerm_orchestrated_virtual_machine_scale_set.aviatrix_scale_set.name,
    "lb_name"                         = var.load_balancer_name,
    "resource_group_name"             = azurerm_resource_group.aviatrix_rg.name,
    "AzureWebJobs.Backup.Disabled"    = var.disable_periodic_backup,
    "SCM_DO_BUILD_DURING_DEPLOYMENT"  = "true",
    "PYTHON_ENABLE_WORKER_EXTENSIONS" = "1",
    "ENABLE_ORYX_BUILD"               = "true",
    "FUNCTIONS_WORKER_RUNTIME"        = "python",
  }

  site_config {
    linux_fx_version          = "Python|3.9"
    ftps_state                = "Disabled"
    http2_enabled             = true
    use_32_bit_worker_process = false
  }

  depends_on = [
    module.aviatrix_controller_initialize
  ]
}

# 11.3. Add Function APP Public IP's to Network Security Group
resource "azurerm_network_security_rule" "function_app_rules" {
  name                        = "httpsFunctionAppInboundToScaleSet"
  resource_group_name         = azurerm_resource_group.aviatrix_rg.name
  network_security_group_name = azurerm_network_security_group.aviatrix_controller_nsg.name
  access                      = "Allow"
  direction                   = "Inbound"
  priority                    = "201"
  protocol                    = "TCP"
  source_port_range           = "*"
  destination_port_range      = "443"
  source_address_prefixes     = split(",", azurerm_function_app.controller_app.possible_outbound_ip_addresses)
  destination_address_prefix  = "*"
  description                 = "Function App Public IP's inbound to scale set"
}

# 11.4. Retrieve Function App Keys
data "azurerm_function_app_host_keys" "func_keys" {
  name                = azurerm_function_app.controller_app.name
  resource_group_name = azurerm_resource_group.aviatrix_rg.name
}

# 12.0 Create Function App Action Group
resource "azurerm_monitor_action_group" "aviatrix_controller_action" {
  lifecycle {
    ignore_changes = [azure_function_receiver[0].http_trigger_url]
  }
  enabled             = true
  name                = var.function_action_group_name
  resource_group_name = azurerm_resource_group.aviatrix_rg.name
  short_name          = "avx-function"
  tags                = {}

  azure_function_receiver {
    function_app_resource_id = azurerm_function_app.controller_app.id
    function_name            = azurerm_function_app.controller_app.name
    http_trigger_url         = "https://${azurerm_function_app.controller_app.default_hostname}/api/Azure-Controller-HA?code=${data.azurerm_function_app_host_keys.func_keys.default_function_key}"
    name                     = "controller-func"
    use_common_alert_schema  = false
  }

  email_receiver {
    email_address           = var.avx_account_email
    name                    = "sendtoadmin"
    use_common_alert_schema = false
  }
}

# 12.1. Create Notification Action Group
resource "azurerm_monitor_action_group" "aviatrix_notification_action_group" {
  count               = var.enable_function_app_alerts ? 1 : 0
  enabled             = true
  name                = var.notification_action_group_name
  resource_group_name = azurerm_resource_group.aviatrix_rg.name
  short_name          = "avx-notify"
  tags                = {}

  email_receiver {
    email_address           = var.avx_account_email
    name                    = "sendtoadmin"
    use_common_alert_schema = false
  }
}

# 12.2. Create Metric Alert for Load Balancer Health
resource "azurerm_monitor_metric_alert" "aviatrix_controller_alert" {
  auto_mitigate       = true
  enabled             = true
  frequency           = "PT1M"
  name                = "${var.scale_set_controller_name}-HealthCheck"
  resource_group_name = azurerm_resource_group.aviatrix_rg.name
  scopes = [
    azurerm_lb.aviatrix_lb.id
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
        "443"
      ]
    }
  }
}

# 12.3. Create Notification Alert for Function App Exception
resource "azurerm_monitor_metric_alert" "function_app_exception_alert" {
  count               = var.enable_function_app_alerts ? 1 : 0
  name                = "Aviatrix Function App Failover - Exception"
  description         = "Sends Error Notification when Azure Aviatrix Controller Function App Exception Occurs."
  resource_group_name = azurerm_resource_group.aviatrix_rg.name
  auto_mitigate       = true
  enabled             = true
  frequency           = "PT1M"
  window_size         = "PT1M"
  scopes = [
    azurerm_application_insights.application_insights.id
  ]
  target_resource_type = "Microsoft.Insights/components"
  severity             = 1

  action {
    action_group_id = var.notification_action_group_id == "" ? azurerm_monitor_action_group.aviatrix_notification_action_group[0].id : var.notification_action_group_id
  }

  criteria {
    metric_name            = "exceptions/server"
    metric_namespace       = "Microsoft.Insights/components"
    aggregation            = "Count"
    operator               = "GreaterThan"
    skip_metric_validation = false
    threshold              = 0
  }
}

# 12.4. Create Notification Alert for Function App Failure
resource "azurerm_monitor_metric_alert" "function_app_failed_alert" {
  count               = var.enable_function_app_alerts ? 1 : 0
  name                = "Aviatrix Function App Failover - Failed"
  description         = "Sends Error Notification when Azure Aviatrix Controller Function App Failover Request Fails."
  resource_group_name = azurerm_resource_group.aviatrix_rg.name
  auto_mitigate       = true
  enabled             = true
  frequency           = "PT1M"
  window_size         = "PT1M"
  scopes = [
    azurerm_application_insights.application_insights.id
  ]
  target_resource_type = "Microsoft.Insights/components"
  severity             = 1

  action {
    action_group_id = var.notification_action_group_id == "" ? azurerm_monitor_action_group.aviatrix_notification_action_group[0].id : var.notification_action_group_id
  }

  criteria {
    metric_name            = "requests/count"
    metric_namespace       = "Microsoft.Insights/components"
    aggregation            = "Count"
    operator               = "GreaterThan"
    skip_metric_validation = false
    threshold              = 0
    dimension {
      name     = "request/resultCode"
      operator = "Exclude"
      values   = ["0", "200", "501"]
    }
  }
}

# 12.5. Create Notification Alert for Function App Success
resource "azurerm_monitor_metric_alert" "function_app_success_alert" {
  count               = var.enable_function_app_alerts ? 1 : 0
  name                = "Aviatrix Function App Failover - Suceeded"
  description         = "Sends Information Notification when Azure Aviatrix Controller Function App Failover Request Succeeds."
  resource_group_name = azurerm_resource_group.aviatrix_rg.name
  auto_mitigate       = true
  enabled             = true
  frequency           = "PT1M"
  window_size         = "PT1M"
  scopes = [
    azurerm_application_insights.application_insights.id
  ]
  target_resource_type = "Microsoft.Insights/components"
  severity             = 3

  action {
    action_group_id = var.notification_action_group_id == "" ? azurerm_monitor_action_group.aviatrix_notification_action_group[0].id : var.notification_action_group_id
  }

  criteria {
    metric_name            = "requests/count"
    metric_namespace       = "Microsoft.Insights/components"
    aggregation            = "Count"
    operator               = "GreaterThan"
    skip_metric_validation = false
    threshold              = 0
    dimension {
      name     = "request/resultCode"
      operator = "Include"
      values   = ["200"]
    }
  }
}

# 13.0. Wait 1 Minute Before Starting the Function App Code
resource "time_sleep" "controller_function_provision" {
  create_duration = "1m"

  triggers = {
    function_id = azurerm_function_app.controller_app.name
  }
}

# 13.1. Create function.json for periodic backup
resource "local_file" "function-json" {
  filename = "${path.module}/azure-controller/Backup/function.json"
  content  = <<-EOT
    {
      "scriptFile": "azure_aviatrix_backup.py",
      "bindings": [
        {
          "name": "mytimer",
          "type": "timerTrigger",
          "direction": "in",
          "schedule": "${var.schedule}"
      }
      ]
    }
  EOT
}

# 13.2. Deploy Controller Function App Code
resource "null_resource" "run_controller_function" {
  depends_on = [
    time_sleep.controller_function_provision
  ]
  provisioner "local-exec" {
    command = "cd ${path.module}/azure-controller && func azure functionapp publish ${azurerm_function_app.controller_app.name} --build remote --python"
  }
}
