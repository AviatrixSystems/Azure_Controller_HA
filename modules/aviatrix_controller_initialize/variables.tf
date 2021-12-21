variable "avx_controller_public_ip" {
  type        = string
  description = "aviatrix controller public ip address(required)"
}

variable "avx_controller_private_ip" {
  type        = string
  description = "aviatrix controller private ip address(required)"
}

variable "avx_controller_admin_email" {
  type        = string
  description = "aviatrix controller admin email address"
}

variable "avx_controller_admin_password" {
  type        = string
  description = "aviatrix controller admin password"
}

variable "arm_subscription_id" {
  type        = string
  description = "Azure subscription id"
}

variable "arm_application_id" {
  type        = string
  description = "Azure application client id"
}

variable "arm_application_key" {
  type        = string
  description = "Azure application client secret"
}

variable "directory_id" {
  type        = string
  description = "Azure directory tenant id"
}

variable "account_email" {
  type        = string
  description = "aviatrix controller access account email"
}

variable "access_account_name" {
  type        = string
  description = "aviatrix controller access account name"
}

variable "aviatrix_customer_id" {
  type        = string
  description = "aviatrix customer license id"
}

variable "terraform_module_path" {
  type        = string
  description = "terraform module absolute path"
  default     = ""
}

variable "controller_version" {
  type        = string
  description = "Aviatrix Controller version"
  default     = "latest"
}
