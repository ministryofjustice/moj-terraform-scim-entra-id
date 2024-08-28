import os
import unittest
from unittest.mock import patch, MagicMock
from moto import mock_aws
import requests_mock
from function.app import lambda_handler

class TestLambdaFunction(unittest.TestCase):

    def setUp(self):
        self.mock_tenant_id = os.environ.get('AZURE_TENANT_ID', 'mock_tenant_id')
        self.mock_access_token_url = f"https://login.microsoftonline.com/{self.mock_tenant_id}/oauth2/v2.0/token"
        self.mock_identity_store_id = 'mocked_identity_store_id'

    @mock_aws
    @requests_mock.Mocker()
    def test_lambda_handler_remove_user(self, mock_requests):
        # Mock Azure token response
        mock_requests.post(
            self.mock_access_token_url,
            json={'access_token': 'mocked_access_token'}
        )

        # Mock Azure group retrieval
        mock_requests.get(
            'https://graph.microsoft.com/v1.0/groups',
            json={'value': [{'id': 'group1', 'displayName': 'aws-sso-group1'}]}
        )

        # Mock Azure group members (users that should remain in the group)
        mock_requests.get(
            'https://graph.microsoft.com/v1.0/groups/group1/members',
            json={'value': [{'userPrincipalName': 'user1@example.com', 'givenName': 'User', 'surname': 'One'}]}
        )

        # Mock Azure group owners (users that should remain in the group)
        mock_requests.get(
            'https://graph.microsoft.com/v1.0/groups/group1/owners',
            json={'value': [{'userPrincipalName': 'admin1@example.com', 'givenName': 'Admin', 'surname': 'One'}]}
        )

        # Mock AWS Identity Store responses
        identity_center_client = MagicMock()
        identity_center_client.list_instances.return_value = {
            'Instances': [{'IdentityStoreId': self.mock_identity_store_id}]
        }
        identity_center_client.create_group.return_value = {'GroupId': 'mocked_group_id'}

        # Mock an extra AWS user that should be removed
        aws_groups = {
            'aws-sso-group1': {
                'GroupId': 'mocked_group_id',
                'Members': {'user1@example.com', 'admin1@example.com', 'extra_user@example.com'}
            }
        }

        # Mock the describe_user to match the extra user
        identity_center_client.describe_user.return_value = {
            'UserName': 'extra_user@example.com',
            'Emails': [{'Value': 'extra_user@example.com', 'Type': 'EntraId', 'Primary': True}]
        }
        identity_center_client.get_group_membership_id.return_value = 'mocked_membership_id'

        event = {"dry_run": False}
        context = None

        with patch('boto3.client', return_value=identity_center_client):
            response = lambda_handler(event, context)

        self.assertEqual(response['statusCode'], 200)

        identity_center_client.delete_group_membership.assert_called_once_with(
            IdentityStoreId=self.mock_identity_store_id,
            MembershipId='mocked_membership_id'
        )

if __name__ == '__main__':
    unittest.main()
