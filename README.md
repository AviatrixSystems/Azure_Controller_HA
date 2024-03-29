# Launch an Aviatrix Controller in Azure with High Availability

## Description

This Terraform module:

- Supports Azure controller deployment with only 6.5 and above versions.
- Creates an Aviatrix Controller in Azure using scale set and load balancer.
- Creates an access account on the controller.
- Creates storage account and container required for backup/function logs.
- Creates a KeyVault to safeguard secrets. 
- Creates an Alert to check the loadbalancer health probes.
- Creates an Azure funtion to manage failover event along with periodic backup if needed.

## Prerequisites

1. [Terraform v0.13+](https://www.terraform.io/downloads.html) - execute terraform files
2. [Python3](https://www.python.org/downloads/)
3. [Azure Functions Core Tools](https://docs.microsoft.com/en-us/azure/azure-functions/functions-run-local?tabs=v4%2Cwindows%2Ccsharp%2Cportal%2Cbash)
4. [Resource Providers](https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/resource-providers-and-types#register-resource-provider-1) mentioned below should be registered in the subscription:
  ``` shell
      Microsoft.Compute
      Microsoft.Storage
      Microsoft.Network
      Microsoft.KeyVault
      Microsoft.ManagedIdentity
      Microsoft.insights
      Microsoft.Web
  ```


## Providers

| Name | Version |
|------|---------|
| <a name="provider_azuread"></a> [azuread](#provider\_azuread) | ~> 2.0 |
| <a name="provider_azurerm"></a> [azurerm](#provider\_azurerm) | ~> 2.0 |
| <a name="provider_null"></a> [null](#provider\_null) | \>= 2.0 |

## Available Modules

Module  | Description |
| ------- | ----------- |
|[aviatrix_controller_arm](https://github.com/AviatrixSystems/terraform-aviatrix-azure-controller/tree/master/modules/aviatrix_controller_azure) |Creates Azure Active Directory Application and Service Principal for Aviatrix access account setup |
|[aviatrix_controller_ha](aviatrix_controller_ha/) |Builds the Aviatrix Controller VM on Azure with HA |
|[aviatrix_controller_initialize](https://github.com/AviatrixSystems/terraform-aviatrix-azure-controller/tree/master/modules/aviatrix_controller_initialize) | Initializes the Aviatrix Controller (setting admin email, setting admin password, upgrading controller version, and setting up access account) |

## Procedures for Building and Initializing a Controller in Azure

### 1. Create the Python virtual environment and install required dependencies

Create the virtual environment.

``` shell
python3 -m venv venv
```

Activate the virtual environment.

``` shell
source venv/bin/activate
```

Install required dependencies.

``` shell
pip install -r requirements.txt
```

### 2. Authenticating to Azure

Login to the Azure CLI using:

```shell
az login
````
*Note: Please refer to the [documentation](https://registry.terraform.io/providers/hashicorp/azuread/latest/docs#authenticating-to-azure-active-directory) for different methods of authentication to Azure, incase above command is not applicable.*

Pick the subscription you want and use it in the command below.

```shell
az account set --subscription <subscription_id>
````

### 3. Applying Terraform configuration

```hcl
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
    source                                         = "github.com/AviatrixSystems/Azure_Controller_HA.git//aviatrix_controller_ha?ref=main"
    subscription_id                                = "<Subscription ID>"                            # Required; Subscription ID where resources are deployed.
    to_be_created_service_principal_name           = "<Name of Service Principal>"                  # Optional; The name of the App Registration/Service Principal to be created.
    create_custom_role                             = true/false                                     # Optional; Creates the App Registration/Service Principal with specific roles instead of 'Contributor' Permissions. Default = false
    resource_group_name                            = "<Name of Resource Group>"                     # Required; Creates a Resource Group with this name.
    location                                       = "<Name of Region/Location>"                    # Required; Creates all resources in this region/location.
    storage_account_name                           = "<Name of Storage Account>"                    # Optional; Creates Storage account with this name. Default = "aviatrixstorage<random hex value>"
    key_vault_name                                 = "<Name of Key Vault>"                          # Optional; Creates Key vault with this name. Default = "aviatrix-key-vault-<random hex value>"
    virtual_network_name                           = "<Name of Virtual Network>"                    # Optional; Creates Virtual Network with this name. Default = "aviatrix-vnet"
    virtual_network_cidr                           = "<Virtual Network Address Space>"              # Optional; Creates Virtual Network with this address space. Default = "10.0.0.0/23"
    subnet_name                                    = "<Name of Subnet>"                             # Optional; Creates Subnet with this name. Default = "aviatrix-subnet"
    subnet_cidr                                    = "<Subnet Cidr>"                                # Optional; Creates Subnet with this cidr. Default = "10.0.0.0/24"
    load_balancer_frontend_public_ip_name          = "<Name of LB Frontend Public IP>"              # Optional; Creates LoadBalancer Frontend IP with this name. Default = "aviatrix-lb-public-ip"
    load_balancer_name                             = "<Name of LoadBalancer>"                       # Optional; Creates LoadBalancer with this name. Default = "aviatrix-lb"
    load_balancer_frontend_name                    = "<Name of LoadBalancer Frontend>"              # Optional; Creates LoadBalancer Frontend Configurations with this name. Default = "aviatrix-lb-frontend"
    load_balancer_controller_backend_pool_name     = "<Name of LoadBalancer Backend Pool>"          # Optional; Creates LoadBalancer Backend Pool with this name. Default = "aviatrix-controller-backend"
    load_balancer_controller_health_probe_name     = "<Name of LoadBalancer Health Probe>"          # Optional; Creates LoadBalancer Health Probe with this name. Default = "aviatrix-controller-probe"
    load_balancer_controller_rule_name             = "<Name of LoadBalancer Rule>"                  # Optional; Creates LoadBalancer Rule with this name. Default = "aviatrix-controller-lb-rule"
    network_security_group_controller_name         = "<Name of Network Security Group>"             # Optional; Creates Network Security Group with this name. Default = "aviatrix-controller-nsg"
    aviatrix_controller_security_group_allowed_ips = [<List of Public IP's to be Allowed>]          # Required; Creates Network Security Group Rule with these allowed IP's.
    controller_virtual_machine_size                = "<Controller VM Size>"                         # Optional; Creates Scale Set with this size Virtual Machine. Default = "Standard_A4_v2"
    scale_set_controller_name                      = "<Controller Scale Set Name>"                  # Optional; Creates Scale Set with this name. Default = "aviatrix-controller-scale-set"
    controller_virtual_machine_admin_username      = "<VM Username>"                                # Optional; Creates Virtual Machine with this username. Default = "aviatrix"
    controller_virtual_machine_admin_password      = "<VM Password>"                                # Optional; Creates Virtual machine with this password. Default = "<autogenerated value>"
    controller_public_ssh_key                      = "<SSH Public Key>"                             # Optional; The Public Key to be used for the Virtual Machine. Default = ""
    avx_access_account_name                        = "<Account Name in Aviatrix Controller>"        # Required; Creates an access account with this name in the Aviatrix Controller.
    avx_account_email                              = "<Account Email Address>"                      # Required; Creates an access account with this email address in the Aviatrix Controller.
    avx_controller_admin_email                     = "<Admin Account Email Address>"                # Required; Adds this email address to admin account in the Aviatrix Controller.
    avx_aviatrix_customer_id                       = "<License ID For Aviatrix Controller>"         # Required; Customer License ID for the Aviatrix Controller.
    avx_controller_admin_password                  = "<Admin Password>"                             # Optional; Changes admin password to this password. Default = "<autogenerated value>"
    avx_controller_version                         = "<Controller Version>"                         # Optional; Upgrades the controller to this version. Default = "latest"
    application_insights_name                      = "<Name of App Insights>"                       # Optional; Creates Application Insights with this name. Default = "aviatrix-function-app-insights"
    app_service_plan_name                          = "<Name of App Service Plan>"                   # Optional; Creates App Service Plan with this name. Default = "aviatrix-function-app-sp"
    function_app_name                              = "<Name of Function App>"                       # Optional; Creates Function App with this name. Default = "aviatrix-controller-app-<random hex value>"
    user_assigned_identity_name                    = "<Name of User Assigned Identity>"             # Optional; Creates a User Assigned Identity with this name. Default = "aviatrix-function-identity"
    aviatrix_function_app_custom_role_name         = "<Name of Custom RBAC Role>"                   # Optional; Creates a Custom Role with permissions for the User Assigned Identity. Default = "aviatrix-function-custom-role"
    function_action_group_name                     = "<Name of Function Action Group>"              # Optional; Creates an Action Group for triggering the Function App with this name. Default = "aviatrix-function-action-group"
    notification_action_group_name                 = "<Name of Notification Action Group>"          # Optional; Creates an Action Group for notifying email with Function App results. Default = "aviatrix-notify-action-group"
    notification_action_group_id                   = "<Azure Resource ID of existing Action Group>" # Optional; Uses an already created Action Group to assign to Function App notifications. Default = ""
    enable_function_app_alerts                     = true/false                                     # Optional; Enable Function App Notifications for success, failure, exception. Default = false
    az_support                                     = true/false                                     # Required; Set to true if the Azure region supports AZ's.
    disable_periodic_backup                        = true/false                                     # Optional; Enable Periodic backup function. Default = true
    schedule                                       = "<Cron Timer>"                                 # Optional; Creates a backup every hour by default when disable_periodic_backup is set to false. Default = "0 0 * * * *"
}
```

### Execute

```shell
terraform init
terraform apply --var-file=<terraform.tfvars>
````

Additional Information:

1. Total expected time for failover ~20 mins
    - ~5 min for azure alert to get fired as controller unhealthy.
    - ~15 min to deploy, initialize, restore the new controller.

2. Make sure to enable the backup on the healthy controller prior to triggering the failover.

3. Failover logs can be viewed in function monitor logs.

4. [List](https://github.com/MicrosoftDocs/azure-docs/blob/main/articles/availability-zones/includes/availability-zone-regions-include.md) of regions that support availability zones for the az_support var.
5. Formatted names of the region for location var, can also be gathered using command below
    ```shell
    az account list-locations -o table
    ````

6. Cron Timer [examples](https://docs.microsoft.com/en-us/azure/azure-functions/functions-bindings-timer?tabs=csharp#ncrontab-examples)

Known Caveat :

1. Function Timeout error can occur during the restore process. In case of this error please login to the new controller to validate if the backup has been restored successfully. 
![ScreenShot](./Restore-error.png)

2. Failover may or may not be triggered when instance is stopped manually. As per azure, this inconsistent behavior is technically by design when manual auto scale feature is used in azure virtual machine scale set.

3. Run ``` python -m pip install -–upgrade pip```, if below error occurs during dependencies installation.
![ScreenShot](./Pip-error.png)

Note:

Alert will not be triggered when instance is deleted. It will only be triggered when loadbalancer health checks are failed.
To test the failover, insert a deny rule on controller SG by blocking https traffic from Azure load balancer(sevice tag).

## **Disclaimer**:

The material embodied in this software/code is provided to you "as-is" and without warranty of any kind, express, implied or otherwise, including without limitation, any warranty of fitness for a particular purpose. In no event shall the Aviatrix Inc. be liable to you or anyone else for any direct, special, incidental, indirect or consequential damages of any kind, or any damages whatsoever, including without limitation, loss of profit, loss of use, savings or revenue, or the claims of third parties, whether or not Aviatrix Inc. has been advised of the possibility of such loss, however caused and on any theory of liability, arising out of or in connection with the possession, use or performance of this software/code.
