# repo-infra

Terraform for the freight-desk automation stack: the Bedrock dispatch
quoting agent in AWS account 210987654321 (eu-central-1) and the Azure
OpenAI deployment used by dock document processing (subscription
sub-vantor-1, westeurope).

Internal clone: `git@git.vantor.example:platform/repo-infra.git`

## Apply

    terraform init
    terraform plan -out tfplan
    terraform apply tfplan

State lives in the shared backend; never commit `*.tfstate`.
