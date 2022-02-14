subscription_id                            = "cb041d9e-984f-46a4-938d-572a08b8c176"
to_be_created_service_principal_name       = "travis-controller-ha-sp"
create_custom_role                         = false
resource_group_name                        = "travis-controller-rg"
location                                   = "South Central US"
storage_account_name                       = "traviscontrollertestsa"
key_vault_name                             = "travis-controller-kv"
virtual_network_name                       = "travis-controller-vnet"
virtual_network_cidr                       = "10.0.0.0/23"
subnet_name                                = "travis-controller-subnet"
subnet_cidr                                = "10.0.0.0/24"
load_balancer_frontend_public_ip_name      = "travis-controller-public-ip"
load_balancer_frontend_name                = "aviatrix-lb-frontend"
load_balancer_name                         = "travis-controller-lb"
load_balancer_controller_backend_pool_name = "aviatrix-controller-backend"
load_balancer_controller_health_probe_name = "aviatrix-controller-probe"
load_balancer_controller_rule_name         = "aviatrix-controller-lb-rule"
network_security_group_controller_name     = "aviatrix-controller-nsg"


aviatrix_controller_security_group_allowed_ips = ["209.169.92.39"]

controller_virtual_machine_size           = "Standard_A4_v2"
scale_set_controller_name                 = "travis-controller-scale-set"
controller_virtual_machine_admin_username = "adminUser"
controller_public_ssh_key                 = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC3e8QwCWEfjbI0VeuqzAfB2YQYlA4uZK70MfUG2kd1AadMs0jJMIurvzpKMgC3hSvIb9s0hGsGLPv7REO+TCtNXS+vhaHkQxVFGnIHTW60IiuFACeDKpJpJXV9VTOATSA5eTHb0rW5nX/x1wCc/JVTeDKaJC/4Qa3sETdinCjX3qmd88AdzXNVJ9p+aPAx1PvJ6qFjyxOdG/GSSQKyhGLzfY2O2c3cWL/eYqkA5Fj6x4PCQMQehmdSJyopCmhISx+GI7lNyf8ovUhekJhBZ+a7wEQcZWOCcdNxkOJN5+ucrgz+m08oq5JWSYyCFtkRrMMVRHIJO3gpXVQ9iWrzVEZiEZS4JyHoGBK8Y1DF4ubIQzhDXdSI8yXTXzGLJcrDsWTscRStR/E/mqhJLT2Dj/1/zs7p6Q0pVR1FNQanL2jgWGjL6ZueSsQYH2j8XF7RzWbjLcH/Bs/xob0zKrJ6m3TSyfMDB2C5ZSHtdVtTWxKDSdifqSws9s8j/2ngaO6KQThH6o0D6H4QXeIHmX6vnn2uUNl0aiPTwrqawT2mt7vlelVMd4MPhitzmQCt5vZ4Mg8AbW4GVjM5x5ToIyxnT10jZJSeERefIrD5AV/c4Sd/MPibw7/6zXYKeARnsOpImdRKMii3jxBYV3E4XyMdXvgXnNqHbMyX74sRMSy0pgKMjw== travis dever@TravisDever-Laptop"
# controller_virtual_machine_admin_password = "CM4kbh{wsahWNbq5.g<Z+4="

avx_controller_admin_email    = "tdever@aviatrix.com"
avx_account_email             = "tdever@aviatrix.com"
# avx_controller_admin_password = "CM4kbh{wsahWNbq5.g<Z+4="
avx_access_account_name       = "travis-testing-account"
avx_aviatrix_customer_id      = "avx-dev-1613002716.89"
avx_controller_version        = "6.5"

application_insights_name = "travis-controller-ai"
app_service_plan_name     = "travis-controller-app-service"
function_app_name         = "travis-controller-function-app"

user_assigned_identity_name            = "travis-controller-user-identity"
aviatrix_function_app_custom_role_name = "travis-controller-custom-role"
