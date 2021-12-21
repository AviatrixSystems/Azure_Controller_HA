/**
 * # Aviatrix Controller ARM
 *
 * This module builds the Azure Active Directory (AAD) Application and Service Principal.
 * If you already have an AAD Application you would like to use then you do not need to
 * use this module.
 */

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 2.0"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = ">= 1.0"
    }
    null = {
      source  = "hashicorp/null"
      version = ">= 2.0"
    }
  }
}


// accept license of Aviatrix Controller
resource "null_resource" "accept_license" {
  provisioner "local-exec" {
    command = "python3 ${var.terraform_module_path == "" ? path.module : format("%s/%s", var.terraform_module_path, "aviatrix_controller_arm")}/accept_license.py"
  }
}


# 1.Create the Azure AD APP
resource "azuread_application" "aviatrix_ad_app" {
  display_name = var.app_name
}

# 2. Create the password for the created APP
resource "azuread_application_password" "aviatrix_app_password" {
  application_object_id = azuread_application.aviatrix_ad_app.id
  end_date              = "2120-12-30T23:00:00Z"
}

# 3. Create SP associated with the APP
resource "azuread_service_principal" "aviatrix_sp" {
  application_id = azuread_application.aviatrix_ad_app.application_id
}

# 4. Create the password for the created SP
resource "azuread_service_principal_password" "aviatrix_sp_password" {
  service_principal_id = azuread_service_principal.aviatrix_sp.id
}

# 5. Create a role assignment for the created SP
data "azurerm_subscription" "main" {}

# 6. Create a custom role if var.create_custom_role = true
# The permissions in this role are based on https://docs.aviatrix.com/HowTos/azure_custom_role.html
resource "azurerm_role_definition" "custom_role" {
  count       = var.create_custom_role ? 1 : 0
  name        = "Aviatrix Controller Custom Role"
  scope       = data.azurerm_subscription.main.id
  description = "Custom role for Aviatrix Controller. Created via Terraform"

  permissions {
    actions = [
      "Microsoft.MarketplaceOrdering/offerTypes/publishers/offers/plans/agreements/*",
      "Microsoft.Compute/*/read",
      "Microsoft.Compute/availabilitySets/*",
      "Microsoft.Compute/virtualMachines/*",
      "Microsoft.Compute/disks/*",
      "Microsoft.Network/*/read",
      "Microsoft.Network/publicIPAddresses/*",
      "Microsoft.Network/networkInterfaces/*",
      "Microsoft.Network/networkSecurityGroups/*",
      "Microsoft.Network/loadBalancers/*",
      "Microsoft.Network/routeTables/*",
      "Microsoft.Network/virtualNetworks/*",
      "Microsoft.Storage/storageAccounts/*",
      "Microsoft.Resources/*/read",
      "Microsoft.Resourcehealth/healthevent/*",
      "Microsoft.Resources/deployments/*",
      "Microsoft.Resources/tags/*",
      "Microsoft.Resources/marketplace/purchase/*",
      "Microsoft.Resources/subscriptions/resourceGroups/*"
    ]
    not_actions = []
  }

  assignable_scopes = [
    data.azurerm_subscription.main.id,
  ]
}

resource "azurerm_role_assignment" "aviatrix_sp_role" {
  scope                = data.azurerm_subscription.main.id
  role_definition_name = var.create_custom_role ? null : "Contributor"
  role_definition_id   = var.create_custom_role ? azurerm_role_definition.custom_role[0].role_definition_resource_id : null
  principal_id         = azuread_service_principal.aviatrix_sp.id
}




