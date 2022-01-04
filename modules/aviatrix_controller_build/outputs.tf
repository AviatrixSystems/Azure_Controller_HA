
output "aviatrix_controller_rg" {
  value = azurerm_resource_group.aviatrix_controller_rg
}

output "aviatrix_controller_lb_public_ip_address" {
  value = azurerm_public_ip.aviatrix_lb_public_ip.ip_address
}

output "aviatrix_loadbalancer_id" {
  value = azurerm_lb.aviatrix_lb.id
}
