# aws-secrets-synchronizer

Kubernetes operator that synchronizes secrets from AWS Secrets Manager with kube secrets.

## Installation

```bash
helm repo add aws-secrets-synchronizer https://reezogit.github.io/aws-secrets-synchronizer
helm install aws-secrets-synchronizer aws-secrets-synchronizer/aws-secrets-synchronizer
```

### Requirements

- Helm v3
- Minimal IAM rights for service account used by operator:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetResourcePolicy",
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret",
        "secretsmanager:ListSecretVersionIds",
        "secretsmanager:ListSecrets"
      ],
      "Resource": [
        "*"
      ]
    }
  ]
}
```

## Configuration

The following table lists the configurable parameters of the aws-secrets-synchronizer chart and their default values.

| Parameter                    | Description                 | Default                    |
|------------------------------|-----------------------------|----------------------------|
| `image.repository`           | Image repository            | `ghcr.io/reezogit`         |
| `image.name`                 | Image name                  | `aws-secrets-synchronizer` |
| `image.tag`                  | Image tag                   | `0.2.1-rc2`                    |
| `image.pullPolicy`           | Image pull policy           | `IfNotPresent`             |
| `replicaCount`               | Replica count               | `1`                        |
| `env`                        | Environment variables       | `{}`                       |
| `resources`                  | Resources                   | `{}`                       |
| `imagePullSecrets`           | Image pull secrets          | `[]`                       |
| `serviceAccount.create`      | Service account creation    | `true`                     |
| `serviceAccount.name`        | Service account name        | `aws-secrets-synchronizer` |
| `serviceAccount.annotations` | Service account annotations | `{}`                       |
| `clusterRole.name`           | Cluster role name           | `aws-secrets-synchronizer` |
