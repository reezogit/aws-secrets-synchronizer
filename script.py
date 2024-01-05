import base64
import json
import os
import time
import logging
import structlog
import boto3
from botocore.exceptions import ClientError
from kubernetes import client, config

AWS_REGION = os.environ['AWS_REGION']
SYNC_INTERVAL = os.getenv('SYNC_INTERVAL', 300)
SYNC_EMPTY = os.getenv('SYNC_EMPTY', 'true')
AWS_TAG_KEY = os.getenv('AWS_TAG_KEY', 'SyncedBy')
AWS_TAG_VALUE = os.getenv('AWS_TAG_VALUE', 'aws-secret-synchronizer')
LOG_LEVEL = os.getenv('LOG_LEVEL', logging.INFO)


def get_base_logger(name=None):
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.dev.set_exc_info,
            structlog.processors.EventRenamer("message"),  # rename 'event' to 'message'
            structlog.processors.TimeStamper(fmt="iso", utc=False),
            structlog.processors.JSONRenderer()
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.getLevelName(LOG_LEVEL)),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=False
    )

    return structlog.get_logger(name=name)


class SecretSyncer:
    """
    SecretSyncer is a class that synchronize AWS Secrets Manager secrets with Kubernetes secrets.
    """
    _base_config = {
        'aws_tag_key': AWS_TAG_KEY,
        'aws_tag_value': AWS_TAG_VALUE,
        'sync_empty': SYNC_EMPTY == 'true',
        'sync_interval': SYNC_INTERVAL,
    }

    def __init__(self):
        # Initialize Kubernetes client
        config.load_incluster_config()
        self.v1_api = client.CoreV1Api()

        # Initiliaze AWS Secrets Manager client
        self.client = boto3.client(
            service_name='secretsmanager',
            region_name=AWS_REGION,
        )

        # Use the default logger if the user did not provide its own.
        self.logger = get_base_logger('SecretSyncer') # not compatible with multiple instances of SecretSyncer

        # Merge default params with user config
        self.params = SecretSyncer._base_config


    def list_aws_secrets_by_tags(self) -> list:
        """
        List all AWS Secrets Manager secrets with the tag key/value pair
        :return: list of secrets
        """
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
        """
        Call AWS Secrets Manager list_secrets API
        :param filters: array of filters
        :param next_token: token to get next page
        :param max_results: max results per page
        :return: TODO
        """
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

    def get_secret_values(self, secret_name):
        """
        Get secret value from AWS Secrets Manager
        :param secret_name
        :return: secret content
        """
        try:
            get_secret_value_response = self.client.get_secret_value(
                SecretId=secret_name
            )
        except ClientError as e:
            # For a list of exceptions thrown, see
            # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
            raise e

        self.logger.info("Secret found", secret_name=secret_name)

        # Decrypts secret using the associated KMS key.
        secret = get_secret_value_response['SecretString']

        return secret

    def get_secret_namespace_tag(self, aws_secret):
        """
        Get secret namespace tag from AWS Secrets Manager
        :param aws_secret
        :return: namespace tag value
        """
        for tag in aws_secret['Tags']:
            if tag['Key'] == 'K8s-Namespace':
                return tag['Value']

        raise Exception("No Namespace tag found for secret: ", aws_secret['Name']) # FIXME Declare a custom error

    def create_or_update_secret(self, namespace, secret_name, data):
        """
        Create or update a secret in Kubernetes
        :param namespace: namespace where to create the secret
        :param secret_name: name of the secret
        :param data: data to store in the secret
        :return: None
        """
        body = client.V1Secret(
            api_version="v1",
            kind="Secret",
            metadata=client.V1ObjectMeta(
                name=secret_name,
                annotations={},
                labels={self.params['aws_tag_key']: self.params['aws_tag_value']}
            ),
            data=data
        )

        try:
            # Check if the secret exists
            existing_data = self.v1_api.read_namespaced_secret(name=secret_name, namespace=namespace)

            # If it exists, replace it
            if existing_data.data != body.data:
                self.v1_api.replace_namespaced_secret(
                    name=secret_name,
                    namespace=namespace,
                    body=body
                )

                self.logger.info("Secret updated", secret_name=secret_name, k8s_namespace=namespace)

                return

            self.logger.info("Secret unchanged", secret_name=secret_name, k8s_namespace=namespace)

        except client.rest.ApiException as e:
            if e.status == 404:
                # If it doesn't exist, create it
                self.v1_api.create_namespaced_secret(
                    namespace=namespace,
                    body=body
                )

                self.logger.info("Secret created", secret_name=secret_name, k8s_namespace=namespace)

                return

            raise e

    def delete_obsolete_secrets(self, existing_kube_secrets, aws_secrets):
        """
        Delete secrets that are not in AWS Secrets Manager anymore
        :param existing_kube_secrets: list of existing secrets in Kubernetes
        :param aws_secrets: list of existing secrets in AWS Secrets Manager
        :return: None
        """
        for existing_kube_secret in existing_kube_secrets.items:
            if existing_kube_secret.metadata.name not in [aws_secret['Name'] for aws_secret in aws_secrets]:
                self.v1_api.delete_namespaced_secret(
                    name=existing_kube_secret.metadata.name,
                    namespace=existing_kube_secret.metadata.namespace,
                    body=client.V1DeleteOptions()
                )

                self.logger.info(
                    "Secret deleted",
                    secret_name=existing_kube_secret.metadata.name,
                    k8s_namespace=existing_kube_secret.metadata.namespace
                )

    def get_encoded_data_to_sync(self, data, sync_empty):
        """
        Encode data to base64 and filter out empty values
        :param data: data to encode
        :param sync_empty: boolean to sync empty values
        :return: encoded data
        """

        # first, filter out empty values if sync_empty is False
        filtered_data = {}
        for key, value in data.items():
            if not value:
                if not sync_empty:
                    self.logger.warning("Empty key removed from synchronization", key=key)

                    continue

                self.logger.warning("Empty key", key=key)
            else:
                filtered_data[key] = value

        # then encode the data to base64
        encoded_data = {}
        for key, value in filtered_data.items():
            encoded_data[key] = base64.b64encode(value.encode()).decode("utf-8")

        return encoded_data

    def run(self):
        """
        Main loop
        :return: None
        """
        while True:
            try:
                self.logger.info("Syncing secrets")
                aws_secrets = self.list_aws_secrets_by_tags()
                self.logger.debug("Got list of secrets", secrets=aws_secrets)
                existing_kube_secrets = self.v1_api.list_secret_for_all_namespaces(
                    watch=False,
                    label_selector=self.params['aws_tag_key'] + "=" + self.params['aws_tag_value']
                )
                self.logger.debug("Existing secrets in k8s secrets", secrets=existing_kube_secrets.items)

                for aws_secret in aws_secrets:
                    try:
                        namespace = self.get_secret_namespace_tag(aws_secret)
                    except Exception as e:  # FIXME Should not catch generic exception, declare a custom one then catch it here
                        self.logger.error(
                            "Failed to get namespace tag from AWS secret",
                            secret_name=aws_secret['Name'],
                            err=e,
                        )

                        continue

                    # get secret data from AWS Secrets Manager
                    data = json.loads(self.get_secret_values(aws_secret['Name']))

                    self.create_or_update_secret(
                        namespace=namespace,
                        secret_name=aws_secret['Name'],
                        data=self.get_encoded_data_to_sync(
                            data,
                            self.params['sync_empty']
                        )
                    )

                self.delete_obsolete_secrets(existing_kube_secrets, aws_secrets)
            except Exception as e:  # FIXME Really a bad practice
                self.logger.error("Woops, something went wrong!", err=e)

            time.sleep(int(self.params['sync_interval']))


SecretSyncer().run()
