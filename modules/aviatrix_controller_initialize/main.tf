/**
 * # Aviatrix Controller Initialize
 *
 * This module executes the initialization script on the Aviatrix Controller.
 */

terraform {
  required_providers {
    null = {
      source = "hashicorp/null"
    }
  }
}

locals {
  option = format("%s/aviatrix_controller_init.py",
    var.terraform_module_path == "" ? path.module : format("%s/%s", var.terraform_module_path, "aviatrix_controller_initialize")
  )
  argument = format("'%s' '%s' '%s' '%s' '%s' '%s' '%s' '%s' '%s' '%s' '%s' '%s'",
    var.avx_controller_public_ip, var.avx_controller_private_ip, var.avx_controller_admin_email,
    var.avx_controller_admin_password, var.arm_subscription_id, var.arm_application_id,
    var.arm_application_key, var.directory_id, var.account_email, var.access_account_name,
    var.aviatrix_customer_id, var.controller_version
  )
}
resource "null_resource" "run_script" {
  provisioner "local-exec" {
    command = "python3 -W ignore ${local.option} ${local.argument}"
  }
}
