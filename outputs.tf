output "avx_controller_lb_public_ip" {
  value       = module.aviatrix_controller_azure.avx_controller_lb_public_ip
  description = "The Public IP Address of the Load Balancer"
}

output "subscription_id" {
  value       = module.aviatrix_controller_azure.subscription_id
  description = "The subscription where the resources are deployed"
}

output "application_client_id" {
  value       = module.aviatrix_controller_azure.application_client_id
  description = "The Application id of the Aviatrix Controller Application"
}

output "directory_id" {
  value       = module.aviatrix_controller_azure.directory_id
  description = "The Directory id of the Aviatrix Controller Application"
}

output "storage_name" {
  value       = module.aviatrix_controller_azure.storage_name
  description = "The name of the storage account for the controller."
}

output "container_name" {
  value       = module.aviatrix_controller_azure.container_name
  description = "The name of the container for the controller backup."
}

output "key_vault_name" {
  value       = module.aviatrix_controller_azure.key_vault_name
  description = "The name of the key vault for controller secrets."
}
