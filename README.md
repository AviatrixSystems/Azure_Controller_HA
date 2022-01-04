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

Please refer to the documentation for
the [azurerm](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs)
and [azuread](https://registry.terraform.io/providers/hashicorp/azuread/latest/docs) Terraform providers to decide how
to authenticate to Azure.

### 3. Applying *.tfvars* configuration


```hcl
app_name                            = "<< app registration name >>"
controller_name                     = "<< controller name can only consist of lowercase letters and numbers, and must be between 3 and 24 characters long >>" 
location                            = "<< location for controller >>"
controller_virtual_machine_size     = "<< controller instance size >>"
controller_vnet_cidr                = "<< vnet cidr >>"
controller_subnet_cidr              = "<< vnet subnet cidr >>"
incoming_ssl_cidr                   = ["<< trusted management cidrs >>"]
// Example incoming_ssl_cidr list: ["1.1.1.1/32","10.10.0.0/16"]
subscription_id                     = "<< subscription id >>"
controller_virtual_machine_admin_username = "<< username for vm instance >>"
controller_virtual_machine_admin_password = "<< password for vm instance >>"
avx_controller_admin_email          = "<< your email address for your admin account >>"
account_email                       = "<< your email address for your access account >>"
avx_controller_admin_password       = "<< your admin password for the Aviatrix Controller >>"
access_account_name                 = "<< your account name mapping to your Azure account >>"
aviatrix_customer_id                = "<< your customer license id >>"
controller_version                  = "<< your controller version >>"
```

*Execute*

```shell
terraform init
terraform apply
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
