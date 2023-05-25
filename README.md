## AWS secrets synchronizer

This is a simple operator to synchronize secrets from AWS Secrets Manager to kube secrets.

## Usage

The operator is designed to run under Kubernetes and is deployed using Helm.
It regularly fetches all AWS secrets with a specific tag and creates, updates or deletes the corresponding secrets in the
Kubernetes cluster.

### Requirements

AWS secrets must have:
- a `Namespace` tag to specify the operator which namespace to create the kube secret into
- a tag corresponding to `TAG_KEY:TAG_VALUE` used to run the operator (see below)

## Environment variables

| Variable name   | Optional | Description                            | Default value              |
|-----------------|----------|----------------------------------------|----------------------------|
| `AWS_REGION`    | false    | AWS region of secrets to synchronize   | None                       |
| `TIME_TO_SLEEP` | true     | Time to sleep between synchronizations | `300`                      |
| `TAG_KEY`       | true     | Tag key used to filter AWS secrets     | `SyncedBy`                 |
| `TAG_VALUE`     | true     | Tag value used to filter AWS secrets   | `aws-secrets-synchronizer` |
