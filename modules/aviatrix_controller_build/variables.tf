variable "location" {
  type        = string
  description = "Resource Group Location for Aviatrix Controller"
  default     = "West US"
}

variable "controller_name" {
  type        = string
  description = "Customized Name for Aviatrix Controller"
}

variable "controller_vnet_cidr" {
  type        = string
  description = "CIDR for controller VNET."
  default     = "10.0.0.0/24"
}

variable "controller_subnet_cidr" {
  type        = string
  description = "CIDR for controller subnet."
  default     = "10.0.0.0/24"
}

variable "controller_virtual_machine_admin_username" {
  type        = string
  description = "Admin Username for the controller virtual machine."
  default     = "aviatrix"
}

variable "controller_virtual_machine_admin_password" {
  type        = string
  description = "Admin Password for the controller virtual machine."
  default     = "aviatrix1234!"
}

variable "controller_virtual_machine_size" {
  type        = string
  description = "Virtual Machine size for the controller."
  default     = "Standard_A4_v2"
}

variable "incoming_ssl_cidr" {
  type        = list(string)
  description = "Incoming cidr for security group used by controller"
}