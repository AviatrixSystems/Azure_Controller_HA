gen_module_docs: fmt
	terraform-docs markdown --hide requirements ./aviatrix_controller_arm > ./aviatrix_controller_arm/README.md
	terraform-docs markdown --hide requirements ./aviatrix_controller_build > ./aviatrix_controller_build/README.md
	terraform-docs markdown --hide requirements ./aviatrix_controller_initialize > ./aviatrix_controller_initialize/README.md

fmt:
	terraform fmt -recursive
