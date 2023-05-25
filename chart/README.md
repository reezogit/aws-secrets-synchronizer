# aws-secrets-synchronizer

This is a simple operator to synchronize secrets from AWS Secrets Manager to kube secrets.

## Installation

```bash
helm install aws-secrets-synchronizer <chart_url>
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
| `image.tag`                  | Image tag                   | `0.0.1-alpha1`             |
| `image.pullPolicy`           | Image pull policy           | `IfNotPresent`             |
| `replicaCount`               | Replica count               | `1`                        |
| `env`                        | Environment variables       | `{}`                       |
| `resources`                  | Resources                   | `{}`                       |
| `imagePullSecrets`           | Image pull secrets          | `[]`                       |
| `serviceAccount.create`      | Service account creation    | `true`                     |
| `serviceAccount.name`        | Service account name        | `aws-secrets-synchronizer` |
| `serviceAccount.annotations` | Service account annotations | `{}`                       |
| `clusterRole.name`           | Cluster role name           | `aws-secrets-synchronizer` |
