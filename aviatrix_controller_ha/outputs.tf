output "avx_controller_lb_public_ip" {
  value       = azurerm_public_ip.aviatrix_lb_public_ip.ip_address
  description = "The Public IP Address of the Load Balancer"
}

output "subscription_id" {
  value       = module.aviatrix_controller_arm.subscription_id
  description = "The subscription where the resources are deployed"
}

output "application_client_id" {
  value       = module.aviatrix_controller_arm.application_id
  description = "The Application id of the Aviatrix Controller Application"
}

output "directory_id" {
  value       = module.aviatrix_controller_arm.directory_id
  description = "The Directory id of the Aviatrix Controller Application"
}

output "storage_name" {
  value       = azurerm_storage_account.aviatrix_controller_storage.name
  description = "The name of the storage account for the controller."
}

output "container_name" {
  value       = azurerm_storage_container.aviatrix_backup_container.name
  description = "The name of the container for the controller backup."
}

output "key_vault_name" {
  value       = azurerm_key_vault.aviatrix_key_vault.name
  description = "The name of the key vault for controller secrets."
}
