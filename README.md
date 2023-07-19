## AWS secrets synchronizer

Kubernetes operator that synchronizes secrets from AWS Secrets Manager with kube secrets.

## Usage

The operator is designed to run under Kubernetes and is deployed using Helm.
It regularly fetches all AWS secrets having a specific tag and creates, updates or deletes the corresponding secrets in the Kubernetes cluster.

### Requirements

AWS secrets must have:
- a `K8S-Namespace` tag to specify the operator which namespace to create the kube secret into
- a tag corresponding to `TAG_KEY:TAG_VALUE` used to run the operator (see below)

## Environment variables

| Variable name            | Optional | Description                                          | Default value              |
|--------------------------|----------|------------------------------------------------------|----------------------------|
| `AWS_REGION`             | false    | AWS region of secrets to synchronize                 | None                       |
| `SYNC_INTERVAL`          | true     | Time to wait between synchronizations                | `300`                      |
| `SYNC_EMPTY`             | true     | If `false`, empty values are ignored in sync process | `true`                     |
| `AWS_TAG_KEY`            | true     | Tag key used to filter AWS secrets                   | `SyncedBy`                 |
| `AWS_TAG_VALUE`          | true     | Tag value used to filter AWS secrets                 | `aws-secrets-synchronizer` |
| `LOG_LEVEL`              | true     | Log level                                            | `INFO`                     |

## Upgrade packages

```bash
virtualenv venv
source venv/bin/activate
pip install -r requirements.txt
# upgrade packages
pip install "<package==version>"
pip freeze > requirements.txt
# exit virtualenv
deactivate
```

See [https://packaging.python.org/en/latest/guides/installing-using-pip-and-virtual-environments/](https://packaging.python.org/en/latest/guides/installing-using-pip-and-virtual-environments/)
