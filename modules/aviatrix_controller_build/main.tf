/**
 * # Aviatrix Controller Build
 *
 * This module builds and launches the Aviatrix Controller VM instance.
 */

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 2.0"
    }
  }
}


# 1. Create an Azure resource group
resource "azurerm_resource_group" "aviatrix_controller_rg" {
  location = var.location
  name     = "${var.controller_name}-rg"
}

# 2. Create the Virtual Network and Subnet
//  Create the Virtual Network
resource "azurerm_virtual_network" "aviatrix_controller_vnet" {
  address_space = [
  var.controller_vnet_cidr]
  location            = var.location
  name                = "${var.controller_name}-vnet"
  resource_group_name = azurerm_resource_group.aviatrix_controller_rg.name
}

//  Create the Subnet
resource "azurerm_subnet" "aviatrix_controller_subnet" {
  name                 = "${var.controller_name}-subnet"
  resource_group_name  = azurerm_resource_group.aviatrix_controller_rg.name
  virtual_network_name = azurerm_virtual_network.aviatrix_controller_vnet.name
  address_prefixes = [
  var.controller_subnet_cidr]
}

# 3. Create Public IP Address for LB
resource "azurerm_public_ip" "aviatrix_lb_public_ip" {
  allocation_method   = "Static"
  location            = azurerm_resource_group.aviatrix_controller_rg.location
  name                = "${var.controller_name}-lb-public-ip"
  resource_group_name = azurerm_resource_group.aviatrix_controller_rg.name
  sku                 = "Standard"
}

# 4. Create the Security Group
//  Create the Controller SG
resource "azurerm_network_security_group" "aviatrix_controller_nsg" {
  location            = azurerm_resource_group.aviatrix_controller_rg.location
  name                = "${var.controller_name}-security-group"
  resource_group_name = azurerm_resource_group.aviatrix_controller_rg.name
  security_rule {
    access                     = "Allow"
    direction                  = "Inbound"
    name                       = "https"
    priority                   = "200"
    protocol                   = "TCP"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefixes    = var.incoming_ssl_cidr
    destination_address_prefix = "*"
    description                = "https-for-vm-management"
  }
}

# 5. Create the virtual machine Scale Set
// Controller Scale Set
resource "azurerm_orchestrated_virtual_machine_scale_set" "aviatrix_controller_scale_set" {
  encryption_at_host_enabled  = false
  instances                   = 1
  location                    = azurerm_resource_group.aviatrix_controller_rg.location
  name                        = var.controller_name
  platform_fault_domain_count = 1
  priority                    = "Regular"
  resource_group_name         = azurerm_resource_group.aviatrix_controller_rg.name
  sku_name                    = var.controller_virtual_machine_size
  zone_balance                = false

  automatic_instance_repair {
    enabled = false
  }

  network_interface {
    dns_servers                   = []
    enable_accelerated_networking = false
    enable_ip_forwarding          = false
    name                          = "${var.controller_name}-nic01"
    network_security_group_id     = azurerm_network_security_group.aviatrix_controller_nsg.id
    primary                       = true

    ip_configuration {
      load_balancer_backend_address_pool_ids = [
        azurerm_lb_backend_address_pool.aviatrix_lb_pool.id,
      ]
      name      = "${var.controller_name}-nic01"
      primary   = true
      subnet_id = azurerm_subnet.aviatrix_controller_subnet.id
      version   = "IPv4"

      public_ip_address {
        idle_timeout_in_minutes = 15
        name                    = "${var.controller_name}-public-ip"
      }
    }
  }

  os_profile {
    linux_configuration {
      admin_username                  = var.controller_virtual_machine_admin_username
      admin_password                  = var.controller_virtual_machine_admin_password
      computer_name_prefix            = "aviatrix-"
      disable_password_authentication = false
      provision_vm_agent              = true
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

# 6. Create load balancer
resource "azurerm_lb" "aviatrix_lb" {
  location            = azurerm_resource_group.aviatrix_controller_rg.location
  name                = "${var.controller_name}-lb"
  resource_group_name = azurerm_resource_group.aviatrix_controller_rg.name
  sku                 = "Standard"
  sku_tier            = "Regional"
  tags                = {}

  frontend_ip_configuration {
    availability_zone = "No-Zone"

    name = "aviatrix-FrontEnd"

    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.aviatrix_lb_public_ip.id

  }
}

# 6.1. Create load balancer backend pool
// Controller backend pool
resource "azurerm_lb_backend_address_pool" "aviatrix_lb_pool" {
  loadbalancer_id = azurerm_lb.aviatrix_lb.id
  name            = "aviatrix-controller-bepool"
}

# 6.2. Create load balancer rule
// Controller
resource "azurerm_lb_rule" "aviatrix_lb_rule" {
  backend_port                   = 443
  disable_outbound_snat          = true
  enable_floating_ip             = false
  enable_tcp_reset               = false
  frontend_ip_configuration_name = "aviatrix-FrontEnd"
  frontend_port                  = 443
  idle_timeout_in_minutes        = 4
  loadbalancer_id                = azurerm_lb.aviatrix_lb.id
  name                           = "aviatrix_controller_lb_rule"
  probe_id                       = azurerm_lb_probe.aviatrix_lb_probe.id
  backend_address_pool_ids       = [azurerm_lb_backend_address_pool.aviatrix_lb_pool.id]
  protocol                       = "TCP"
  resource_group_name            = azurerm_resource_group.aviatrix_controller_rg.name
}

# 6.3. Create load balancer health probe
// Controller
resource "azurerm_lb_probe" "aviatrix_lb_probe" {
  interval_in_seconds = 5
  loadbalancer_id     = azurerm_lb.aviatrix_lb.id
  name                = "aviatrix-controller-tcpProbe"
  number_of_probes    = 2
  port                = 443
  protocol            = "TCP"
  resource_group_name = azurerm_resource_group.aviatrix_controller_rg.name
}
