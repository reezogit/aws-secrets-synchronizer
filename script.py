import base64
import json
import os
import time
import logging
import boto3
from botocore.exceptions import ClientError
from kubernetes import client, config

tag_key = 'SyncedBy'
tag_value = 'aws-secretmanager-worker'
secret_label = "aws-secret"
secret_label_value = "true"
default_time_to_sleep = 300


# list secret from AWS Secrets manager
def list_aws_secrets_by_tags(region_name):
    client = boto3.client(
        service_name='secretsmanager',
        region_name=region_name,
    )

    try:
        get_secret_value_response = client.list_secrets(Filters=[
            {
                'Key': 'tag-key',
                'Values': [
                    tag_key,
                ],
            },
            {
                'Key': 'tag-value',
                'Values': [
                    tag_value,
                ],
            },
        ], )
    except ClientError as e:
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_ListSecrets.html
        raise e

    secrets = get_secret_value_response['SecretList']

    return secrets


# get secret from AWS Secrets Manager
def get_secret_values(secret_name, region_name):
    logging.info("Getting secret: %s", secret_name)
    client = boto3.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        raise e

    # Decrypts secret using the associated KMS key.
    secret = get_secret_value_response['SecretString']

    return secret


# get secret from AWS Secrets Manager
def get_secret_namespace_tag(aws_secret):
    for tag in aws_secret['Tags']:
        if tag['Key'] == 'Namespace':
            return tag['Value']
    raise Exception("No Namespace tag found for secret: ", aws_secret['Name'])


def create_or_update_secret(core_client, namespace, name, data):
    body = client.V1Secret(
        api_version="v1",
        kind="Secret",
        metadata=client.V1ObjectMeta(name=name, annotations={}, labels={secret_label: secret_label_value}),
        data=data
    )
    try:
        # Check if the secret already exists
        existing_data = core_client.read_namespaced_secret(name=name, namespace=namespace)
        # If it exists, replace it
        if existing_data.data != body.data:
            logging.info("Updating secret: %s", name)
            core_client.replace_namespaced_secret(
                name=name,
                namespace=namespace,
                body=body
            )
        else:
            logging.info("No change in secret: %s", name)

    except client.rest.ApiException as e:
        if e.status == 404:
            # If it doesn't exist, create it
            logging.info("Secret not found, creating secret: %s", name)
            core_client.create_namespaced_secret(
                namespace=namespace,
                body=body
            )
        else:
            raise e


def delete_obsolete_secrets(core_client, existing_kube_secrets, aws_secrets):
    for existing_kube_secret in existing_kube_secrets.items:
        if existing_kube_secret.metadata.name not in [aws_secret['Name'] for aws_secret in aws_secrets]:
            logging.info("Deleting secret: %s", existing_kube_secret.metadata.name)
            core_client.delete_namespaced_secret(
                name=existing_kube_secret.metadata.name,
                namespace=existing_kube_secret.metadata.namespace,
                body=client.V1DeleteOptions()
            )


def main():
    region_name = os.environ['AWS_REGION']
    time_to_sleep = os.environ['TIME_TO_SLEEP'] if 'TIME_TO_SLEEP' in os.environ else default_time_to_sleep
    # Fetching and loading local Kubernetes Information
    config.load_incluster_config()
    v1_api = client.CoreV1Api()
    logging.basicConfig(level=logging.INFO)
    while True:
        try:
            aws_secrets = list_aws_secrets_by_tags(region_name)
            existing_kube_secrets = v1_api.list_secret_for_all_namespaces(watch=False, label_selector=secret_label + "=" + secret_label_value)
            for aws_secret in aws_secrets:
                try:
                    namespace = get_secret_namespace_tag(aws_secret)
                except Exception as e:
                    logging.error(e)
                    continue
                # get secret data from AWS Secrets Manager
                data = json.loads(get_secret_values(aws_secret['Name'], region_name))
                # encode data values to base64
                for key, value in data.items():
                    if value is None:
                        logging.warning("Secret %s has no value for key %s, skipping sync for this key", aws_secret['Name'], key)
                    else:
                        data[key] = base64.b64encode(value.encode()).decode("utf-8")

                create_or_update_secret(core_client=v1_api,
                                        namespace=namespace,
                                        name=aws_secret['Name'],
                                        data=data)

            delete_obsolete_secrets(v1_api, existing_kube_secrets, aws_secrets)

        except Exception as e:
            logging.error(e)

        time.sleep(time_to_sleep)


if __name__ == "__main__":
    main()
