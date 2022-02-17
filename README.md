# Launch an Aviatrix Controller in Azure with High Availbility

## Description

This Terraform module:

- Creates an Aviatrix Controller in Azure using scale set and load balancer.
- Creates an access account on the controller.
- Creates storage and container required for backup/function logs.
- Creates an Alert to check the loadbalancer health probes.
- Creates an azure funtion to manage failover event.

## Prerequisites

1. [Terraform v0.13+](https://www.terraform.io/downloads.html) - execute terraform files
2. [Python3](https://www.python.org/downloads/) - execute `accept_license.py` and `aviatrix_controller_init.py` python
   scripts
3. [Azure Functions Core Tools](https://docs.microsoft.com/en-us/azure/azure-functions/functions-run-local?tabs=v4%2Cwindows%2Ccsharp%2Cportal%2Cbash)

## Providers

The module `aviatrix_controller_arm` does not currently support `azuread` version 2.0 and above. You can use the [pessimistic constraint operator](https://www.terraform.io/docs/language/expressions/version-constraints.html#gt--1) in your `required_providers` configuration to use the latest version 1.x release of `azuread`.

| Name | Version |
|------|---------|
| <a name="provider_azuread"></a> [azuread](#provider\_azuread) | ~> 1.0 |
| <a name="provider_azurerm"></a> [azurerm](#provider\_azurerm) | \>= 2.0 |
| <a name="provider_null"></a> [null](#provider\_null) | \>= 2.0 |

## Available Modules

Module  | Description |
| ------- | ----------- |
|[aviatrix_controller_arm](modules/aviatrix_controller_arm) |Creates Azure Active Directory Application and Service Principal for Aviatrix access account setup |
|[aviatrix_controller_build](modules/aviatrix_controller_build) |Builds the Aviatrix Controller VM on Azure |
|[aviatrix_controller_initialize](modules/aviatrix_controller_initialize) | Initializes the Aviatrix Controller (setting admin email, setting admin password, upgrading controller version, and setting up access account) |

## Procedures for Building and Initializing a Controller in Azure

### Create the Python virtual environment and install required dependencies

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

### Authenticating to Azure

Please refer to the documentation for
the [azurerm](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs)
and [azuread](https://registry.terraform.io/providers/hashicorp/azuread/latest/docs) Terraform providers to decide how
to authenticate to Azure.

Pick the subscription you want and use it in the command below.

```shell
az account set --subscription <subscription_id>
````

### Applying .tfvars configuration

```hcl
# Resource Group Variables
subscription_id                                = "<Subscription ID>"                   # Required; Subscription ID where resources are deployed.
to_be_created_service_principal_name           = "<Name of Service Principal>"         # Optional; The name of the App Registration/Service Principal to be created.
create_custom_role                             = true/false                            # Optional; Creates the App Registration/Service Principal with specific roles instead of 'Contributor' Permissions. Default = false
resource_group_name                            = "<Name of Resource Group>"            # Required; Creates a Resource Group with this name.
location                                       = "<Name of Region/Location>"           # Required; Creates all resources in this region/location.
storage_account_name                           = "<Name of Storage Account>"           # Optional; Creates Storage account with this name. Default = "aviatrixstorage<random hex value>"
key_vault_name                                 = "<Name of Key Vault>"                 # Optional; Creates Key vault with this name. Default = "aviatrix-key-vault-<random hex value>"
virtual_network_name                           = "<Name of Virtual Network>"           # Optional; Creates Virtual Network with this name. Default = "aviatrix-vnet"
virtual_network_cidr                           = "<Virtual Network Address Space>"     # Optional; Creates Virtual Network with this address space. Default = "10.0.0.0/23"
subnet_name                                    = "<Name of Subnet>"                    # Optional; Creates Subnet with this name. Default = "aviatrix-subnet"
subnet_cidr                                    = "<Subnet Cidr>"                       # Optional; Creates Subnet with this cidr. Default = "10.0.0.0/24"
load_balancer_frontend_public_ip_name          = "<Name of LB Frontend Public IP>"     # Optional; Creates LoadBalancer Frontend IP with this name. Default = "aviatrix-lb-public-ip"
load_balancer_name                             = "<Name of LoadBalancer>"              # Optional; Creates LoadBalancer with this name. Default = "aviatrix-lb"
load_balancer_frontend_name                    = "<Name of LoadBalancer Frontend>"     # Optional; Creates LoadBalancer Frontend Configurations with this name. Default = "aviatrix-lb-frontend"
load_balancer_controller_backend_pool_name     = "<Name of LoadBalancer Backend Pool>" # Optional; Creates LoadBalancer Backend Pool with this name. Default = "aviatrix-controller-backend"
load_balancer_controller_health_probe_name     = "<Name of LoadBalancer Health Probe>" # Optional; Creates LoadBalancer Health Probe with this name. Default = "aviatrix-controller-probe"
load_balancer_controller_rule_name             = "<Name of LoadBalancer Rule>"         # Optional; Creates LoadBalancer Rule with this name. Default = "aviatrix-controller-lb-rule"
network_security_group_controller_name         = "<Name of Network Security Group>"    # Optional; Creates Network Security Group with this name. Default = "aviatrix-controller-nsg"
aviatrix_controller_security_group_allowed_ips = [<List of Public IP's to be Allowed>] # Optional; Creates Network Security Group Rule with these allowed IP's. Default = []

# Aviatrix Controller Virtual Machine Variables
controller_virtual_machine_size           = "<Controller VM Size>"                     # Optional; Creates Scale Set with this size Virtual Machine. Default = "Standard_A4_v2"
scale_set_controller_name                 = "<Controller Scale Set Name>"              # Optional; Creates Scale Set with this name. Default = "aviatrix-controller-scale-set"
controller_virtual_machine_admin_username = "<VM Username>"                            # Optional; Creates Virtual Machine with this username. Default = "aviatrix"
controller_virtual_machine_admin_password = "<VM Password>"                            # Optional; Creates Virtual machine with this password. Default = "<autogenerated value>"
controller_public_ssh_key                 = "<SSH Public Key>"                         # Optional; The Public Key to be used for the Virtual Machine. Default = ""

# Aviatrix Controller Configuration Variables
avx_access_account_name       = "<Account Name in Aviatrix Controller>" # Required; Creates an access account with this name in the Aviatrix Controller.
avx_account_email             = "<Account Email Address>"               # Required; Creates an access account with this email address in the Aviatrix Controller.
avx_controller_admin_email    = "<Admin Account Email Address>"         # Required; Adds this email address to admin account in the Aviatrix Controller.
avx_aviatrix_customer_id      = "<License ID For Aviatrix Controller>"  # Required; Customer License ID for the Aviatrix Controller.
avx_controller_admin_password = "<Admin Password>"                      # Optional; Changes admin password to this password. Default = "<autogenerated value>"
avx_controller_version        = "<Controller Version>"                  # Optional; Upgrades the controller to this version. Default = "latest"

# Function App Variables
application_insights_name              = "<Name of App Insights>"                       # Optional; Creates Application Insights with this name. Default = "aviatrix-function-app-insights"
app_service_plan_name                  = "<Name of App Service Plan>"                   # Optional; Creates App Service Plan with this name. Default = "aviatrix-function-app-sp"
function_app_name                      = "<Name of Function App>"                       # Optional; Creates Function App with this name. Default = "aviatrix-controller-app-<random hex value>"
user_assigned_identity_name            = "<Name of User Assigned Identity>"             # Optional; Creates a User Assigned Identity with this name. Default = "aviatrix-function-identity"
aviatrix_function_app_custom_role_name = "<Name of Custom RBAC Role>"                   # Optional; Creates a Custom Role with permissions for the User Assigned Identity. Default = "aviatrix-function-custom-role"
function_action_group_name             = "<Name of Function Action Group>"              # Optional; Creates an Action Group for triggering the Function App with this name. Default = "aviatrix-function-action-group"
notification_action_group_name         = "<Name of Notification Action Group>"          # Optional; Creates an Action Group for notifying email with Function App results. Default = "aviatrix-notify-action-group"
notification_action_group_id           = "<Azure Resource ID of existing Action Group>" # Optional; Uses an already created Action Group to assign to Function App notifications. Default = ""
enable_function_app_alerts             = "<True/False>"                                 # Optional; Enable Function App Notifications for success, failure, exception. Default = false
```

### Execute

```shell
terraform init
terraform apply --var-file=<terrraform.tfvars>
````

Additional Information:

1. Total expected time for failover ~20 mins
    - ~5 min for azure alert to get fired as controller unhealthy.
    - ~15 min to deploy, initialize, restore the new controller.

2. Makes sure to enable the backup on the healthy controller prior to triggering the failover.

3. Failover logs can be viewed in function monitor logs.

Note:

Alert will not be triggered when instance is deleted or stopped manually. It will only be triggered when loadbalancer health checks are failed.
To test the failover, insert a deny rule on controller SG by blocking https traffic from Azure load balancer(sevice tag).
