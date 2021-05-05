# Azure DevOps PAT CLI

An unofficial CLI script that generates [Azure DevOps PATs](https://docs.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate).

This relies on private APIs and may stop working at any time. It
should only be used in non-critical environments.

Contributions welcome.

## Setup

```
git clone https://github.com/libcthorne/azure-devops-pat-cli.git
cd azure-devops-pat-cli
pip install -r requirements.txt
```

Required environment variables:
- `AZURE_DEVOPS_USERNAME` (e.g. `john@smith.og`)
- `AZURE_DEVOPS_PASSWORD` (e.g. `s3cr3t`)
- `AZURE_DEVOPS_PROJECT` (should match URL: `https://dev.azure.com/<project>/`)

Optional environment variables:
- `AZURE_DEVOPS_PAT_NAME` (default: `ScriptGeneratedPAT`)
- `AZURE_DEVOPS_PAT_SCOPES` (default: `vso.packaging_write`)
- `AZURE_DEVOPS_PAT_ALWAYS_CREATE` (default: disabled)

## Basic usage example

```
export AZURE_DEVOPS_USERNAME='john@smith.org'
export AZURE_DEVOPS_PASSWORD='s3cr3t'
export AZURE_DEVOPS_PROJECT='mozilla'
python pat_cli.py
```
->
```
Starting authentication flow
Starting standard AD login flow
Created new PAT:
<PAT printed here>
```

## Using together with other scripts

```
export AZURE_DEVOPS_USERNAME='john@smith.org'
export AZURE_DEVOPS_PASSWORD='s3cr3t'
export AZURE_DEVOPS_PROJECT='mozilla'
echo "PAT = $(python pat_cli.py | tee /dev/tty | tail -1)"
```
->
```
PAT = <PAT printed here>
```
