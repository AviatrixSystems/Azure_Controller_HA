output "avx_controller_lb_public_ip" {
  value = azurerm_public_ip.aviatrix_lb_public_ip.ip_address
}
