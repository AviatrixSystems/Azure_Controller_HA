output "avx_controller_lb_public_ip" {
  value       = module.aviatrix_controller_azure.avx_controller_lb_public_ip
  description = "The Public IP Address of the Load Balancer"
}
