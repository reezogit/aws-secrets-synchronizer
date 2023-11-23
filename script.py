import base64
import json
import os
import time
import logging
import boto3
from botocore.exceptions import ClientError
from kubernetes import client, config


class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "application_name": "aws-secrets-synchronizer",
            "level": record.levelname,
            "msg": record.getMessage()
        }
        return json.dumps(log_record)


class SecretSyncer:
    def __init__(self, v1_api, region_name, logger, params):
        self.v1_api = v1_api
        self.client = boto3.client(
            service_name='secretsmanager',
            region_name=region_name,
        )
        self.region_name = region_name
        self.logger = logger
        # merge default params with params passed in
        self.params = {
            'aws_tag_key': 'SyncedBy',
            'aws_tag_value': 'aws-secrets-synchronizer',
            'sync_empty': True,
            'sync_interval': 300,
        }
        self.params.update(params)

    # list secret from AWS Secrets manager
    def list_aws_secrets_by_tags(self):
        secrets = []
        filters = [
            {
                'Key': 'tag-key',
                'Values': [
                    self.params['aws_tag_key'],
                ],
            },
            {
                'Key': 'tag-value',
                'Values': [
                    self.params['aws_tag_value'],
                ],
            },
        ]

        # first call
        get_secret_value_response = self.aws_list_secrets_call(filters)
        secrets.extend(get_secret_value_response['SecretList'])
        next_token = get_secret_value_response.get('NextToken', None)

        # next calls
        while next_token is not None:
            get_secret_value_response = self.aws_list_secrets_call(filters, next_token)
            secrets.extend(get_secret_value_response['SecretList'])
            next_token = get_secret_value_response.get('NextToken', None)

        return secrets

    def aws_list_secrets_call(self, filters, next_token=None, max_results=100):
        try:
            if next_token is None:
                get_secret_value_response = self.client.list_secrets(
                    MaxResults=max_results,
                    Filters=filters
                )
            else:
                get_secret_value_response = self.client.list_secrets(
                    MaxResults=max_results,
                    NextToken=next_token,
                    Filters=filters
                )

        except ClientError as e:
            # For a list of exceptions thrown, see
            # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_ListSecrets.html
            raise e

        return get_secret_value_response

    # get secret from AWS Secrets Manager
    def get_secret_values(self, secret_name):
        self.logger.info("Getting secret: %s", secret_name)

        try:
            get_secret_value_response = self.client.get_secret_value(
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
    def get_secret_namespace_tag(self, aws_secret):
        for tag in aws_secret['Tags']:
            if tag['Key'] == 'K8s-Namespace':
                return tag['Value']
        raise Exception("No Namespace tag found for secret: ", aws_secret['Name'])

    def create_or_update_secret(self, namespace, name, data):
        body = client.V1Secret(
            api_version="v1",
            kind="Secret",
            metadata=client.V1ObjectMeta(name=name, annotations={},
                                         labels={self.params['aws_tag_key']: self.params['aws_tag_value']}),
            data=data
        )
        try:
            # Check if the secret already exists
            existing_data = self.v1_api.read_namespaced_secret(name=name, namespace=namespace)
            # If it exists, replace it
            if existing_data.data != body.data:
                self.logger.info("Updating secret: %s in namespace: %s", name, namespace)
                self.v1_api.replace_namespaced_secret(
                    name=name,
                    namespace=namespace,
                    body=body
                )
            else:
                self.logger.info("No change in secret: %s", name)

        except client.rest.ApiException as e:
            if e.status == 404:
                # If it doesn't exist, create it
                self.logger.info("Secret not found, creating secret: %s in namespace: %s", name, namespace)
                self.v1_api.create_namespaced_secret(
                    namespace=namespace,
                    body=body
                )
            else:
                raise e

    def delete_obsolete_secrets(self, existing_kube_secrets, aws_secrets):
        for existing_kube_secret in existing_kube_secrets.items:
            if existing_kube_secret.metadata.name not in [aws_secret['Name'] for aws_secret in aws_secrets]:
                self.logger.info("Deleting secret: %s in namespace: %s", existing_kube_secret.metadata.name,
                                 existing_kube_secret.metadata.namespace)
                self.v1_api.delete_namespaced_secret(
                    name=existing_kube_secret.metadata.name,
                    namespace=existing_kube_secret.metadata.namespace,
                    body=client.V1DeleteOptions()
                )

    def get_encoded_data_to_sync(self, data, sync_empty):
        # first, filter out empty values if sync_empty is False
        filtered_data = {}
        for key, value in data.items():
            if value is None and sync_empty is False:
                self.logger.warning("Key %s has an empty value, removed from synchronization.", key)
                continue
            elif value is None:
                self.logger.warning("Key %s has an empty value.", key)
            else:
                filtered_data[key] = value

        # then encode the data to base64
        encoded_data = {}
        for key, value in filtered_data.items():
            encoded_data[key] = base64.b64encode(value.encode()).decode("utf-8")

        return encoded_data

    def run(self):
        while True:
            try:
                aws_secrets = self.list_aws_secrets_by_tags()
                existing_kube_secrets = self.v1_api.list_secret_for_all_namespaces(
                    watch=False,
                    label_selector=self.params['aws_tag_key'] + "=" + self.params['aws_tag_value'])
                for aws_secret in aws_secrets:
                    try:
                        namespace = self.get_secret_namespace_tag(aws_secret)
                    except Exception as e:
                        self.logger.error(e)
                        continue
                    # get secret data from AWS Secrets Manager
                    data = json.loads(self.get_secret_values(aws_secret['Name']))
                    self.create_or_update_secret(namespace=namespace,
                                                 name=aws_secret['Name'],
                                                 data=self.get_encoded_data_to_sync(data, self.params['sync_empty']))

                self.delete_obsolete_secrets(existing_kube_secrets, aws_secrets)

            except Exception as e:
                self.logger.error(e)

            time.sleep(self.params['sync_interval'])


def main():
    params = {}
    if 'SYNC_INTERVAL' in os.environ:
        params['sync_interval'] = int(os.environ['SYNC_INTERVAL'])
    if 'SYNC_EMPTY' in os.environ:
        params['sync_empty'] = os.environ['SYNC_EMPTY'] == 'true'
    if 'AWS_TAG_KEY' in os.environ:
        params['aws_tag_key'] = os.environ['AWS_TAG_KEY']
    if 'AWS_TAG_VALUE' in os.environ:
        params['aws_tag_value'] = os.environ['AWS_TAG_VALUE']

    config.load_incluster_config()

    # create logger with JSON formatter
    logger = logging.getLogger('json_logger')
    log_handler = logging.StreamHandler()
    log_handler.setFormatter(JsonFormatter())
    logger.addHandler(log_handler)
    logger.setLevel(os.environ.get('LOG_LEVEL', logging.INFO))

    secret_syncer = SecretSyncer(
        client.CoreV1Api(),
        os.environ['AWS_REGION'],
        logger,
        params
    )
    secret_syncer.run()


if __name__ == "__main__":
    main()
