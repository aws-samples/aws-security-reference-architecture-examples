# SRA-Terraform

## Prerequisites
- Terraform version >= 1.0

## Installaing Common Pre-Reqs
This will install the common pre-reqs by initializing the SSM parameters into your control tower environment for usage by later modules.

NOTE: Please edit the variables.tf or pass in the variables in CLI if you do not plan to use CT. Set it to false and setup the required parameters.

```bash
cd common
terraform init
terraform plan
terraform apply
```

After the apply, TF will create two files in your solutions folder (backend.tfvars and config.tfvars)
## Configuring Modules
```hcl
cd solutions
```

Edit the configs.tfvars as needed to customize for your environment.

## Terraform "Stackset" Deployment

Inside the SRA directory includes a python script that emulates deployment of stacksets for the SRA module in terraform. This ensures that all accounts get deployed to correctly.

```bash
python3 terraform_stack.py
python3 terraform_stack.py init
python3 terraform_stack.py plan
python3 terraform_stack.py apply
```