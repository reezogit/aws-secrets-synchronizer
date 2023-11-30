import base64
import json
import unittest
from unittest.mock import patch, MagicMock
from script import SecretSyncer


class TestSecretSyncer(unittest.TestCase):
    @patch('kubernetes.config.load_incluster_config')
    @patch('kubernetes.client.CoreV1Api')
    def setUp(self, mock_core_v1_api, mock_load_config):
        mock_load_config.return_value = None

        # Mock CoreV1Api
        self.mock_core_v1_api = MagicMock()
        mock_core_v1_api.return_value = self.mock_core_v1_api

        self.config = {
            'sync_interval': 300,
            'sync_empty': True,
            'aws_tag_key': 'SyncedBy',
            'aws_tag_value': 'aws-secrets-synchronizer',
        }

        self.secret_syncer = SecretSyncer(cfg=self.config)

    @patch('boto3.client')
    def test_list_aws_secrets_by_tags(self, mock_boto_client):
        # Mock the AWS client response
        mock_boto_client.return_value.list_secrets.return_value = {
            'SecretList': [{'Name': 'secret1'}, {'Name': 'secret2'}],
            'NextToken': None
        }

        secrets = self.secret_syncer.list_aws_secrets_by_tags()

        # Assert that the AWS client was called and the correct number of secrets were returned
        mock_boto_client.return_value.list_secrets.assert_called_once()
        self.assertEqual(len(secrets), 2)

    @patch('boto3.client')
    def test_get_secret_values(self, mock_boto_client):
        # Mock the AWS client response
        mock_boto_client.return_value.get_secret_value.return_value = {
            'SecretString': '{"key": "value"}'
        }

        secret = self.secret_syncer.get_secret_values("mysecret")

        # Assert that the secret is correctly fetched and parsed
        self.assertEqual(json.loads(secret), {"key": "value"})

    def test_get_encoded_data_to_sync(self):
        data = {"key1": "value1", "key2": ""}
        encoded_data = self.secret_syncer.get_encoded_data_to_sync(data, self.config['sync_empty'])

        # Assert that the data is encoded correctly
        self.assertEqual(encoded_data["key1"], base64.b64encode("value1".encode()).decode())
        self.assertTrue("key2" not in encoded_data or encoded_data["key2"] == "")
