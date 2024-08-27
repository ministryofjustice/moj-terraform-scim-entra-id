import unittest
from unittest.mock import patch, MagicMock
from moto import mock_aws
import requests_mock
from function.app import lambda_handler

class TestLambdaFunction(unittest.TestCase):

    @mock_aws
    @requests_mock.Mocker()
    def test_lambda_handler_add_user(self, mock_requests):
        # Mock Azure token response
        mock_requests.post(
            'https://login.microsoftonline.com/mock_tenant_id/oauth2/v2.0/token',
            json={'access_token': 'mocked_access_token'}
        )

        # Mock Azure group retrieval
        mock_requests.get(
            'https://graph.microsoft.com/v1.0/groups',
            json={'value': [{'id': 'group1', 'displayName': 'entraid-aws-identitycenter-group1'}]}
        )

        # Mock Azure group members
        mock_requests.get(
            'https://graph.microsoft.com/v1.0/groups/group1/members',
            json={'value': [{'userPrincipalName': 'user1@example.com', 'givenName': 'User', 'surname': 'One'}]}
        )

        # Mock Azure group owners
        mock_requests.get(
            'https://graph.microsoft.com/v1.0/groups/group1/owners',
            json={'value': [{'userPrincipalName': 'admin1@example.com', 'givenName': 'Admin', 'surname': 'One'}]}
        )

        # Mock AWS Identity Store responses
        identity_center_client = MagicMock()
        identity_center_client.create_group.return_value = {'GroupId': 'mocked_group_id'}
        identity_center_client.create_user.return_value = {'UserId': 'mocked_user_id'}

        event = {"dry_run": False}
        context = None

        response = lambda_handler(event, context)

        self.assertEqual(response['statusCode'], 200)
        identity_center_client.create_group.assert_called_once_with(
            IdentityStoreId='mocked_identity_store_id',
            DisplayName='entraid-aws-identitycenter-group1'
        )
        identity_center_client.create_user.assert_called_once()

    @mock_aws
    @requests_mock.Mocker()
    def test_lambda_handler_remove_user(self, mock_requests):
        # Mock Azure token response
        mock_requests.post(
            'https://login.microsoftonline.com/mock_tenant_id/oauth2/v2.0/token',
            json={'access_token': 'mocked_access_token'}
        )

        # Mock Azure group retrieval
        mock_requests.get(
            'https://graph.microsoft.com/v1.0/groups',
            json={'value': [{'id': 'group1', 'displayName': 'entraid-aws-identitycenter-group1'}]}
        )

        # Mock Azure group members
        mock_requests.get(
            'https://graph.microsoft.com/v1.0/groups/group1/members',
            json={'value': []}  # Simulate user removal
        )

        # Mock Azure group owners
        mock_requests.get(
            'https://graph.microsoft.com/v1.0/groups/group1/owners',
            json={'value': []}  # Simulate user removal
        )

        # Mock AWS Identity Store responses
        identity_center_client = MagicMock()
        identity_center_client.list_group_memberships.return_value = {
            'GroupMemberships': [
                {'MemberId': {'UserId': 'mocked_user_id'}}
            ]
        }

        event = {"dry_run": False}
        context = None

        response = lambda_handler(event, context)

        self.assertEqual(response['statusCode'], 200)
        identity_center_client.delete_group_membership.assert_called_once()

    @mock_aws
    @requests_mock.Mocker()
    def test_lambda_handler_sync_users_and_groups(self, mock_requests):
        # Mock Azure token response
        mock_requests.post(
            'https://login.microsoftonline.com/mock_tenant_id/oauth2/v2.0/token',
            json={'access_token': 'mocked_access_token'}
        )

        # Mock Azure group retrieval
        mock_requests.get(
            'https://graph.microsoft.com/v1.0/groups',
            json={'value': [
                {'id': 'group1', 'displayName': 'entraid-aws-identitycenter-group1'},
                {'id': 'group2', 'displayName': 'entraid-aws-identitycenter-group2'}
            ]}
        )

        # Mock Azure group members
        mock_requests.get(
            'https://graph.microsoft.com/v1.0/groups/group1/members',
            json={'value': [{'userPrincipalName': 'user1@example.com', 'givenName': 'User', 'surname': 'One'}]}
        )
        mock_requests.get(
            'https://graph.microsoft.com/v1.0/groups/group2/members',
            json={'value': [{'userPrincipalName': 'user2@example.com', 'givenName': 'User', 'surname': 'Two'}]}
        )

        # Mock Azure group owners
        mock_requests.get(
            'https://graph.microsoft.com/v1.0/groups/group1/owners',
            json={'value': []}
        )
        mock_requests.get(
            'https://graph.microsoft.com/v1.0/groups/group2/owners',
            json={'value': []}
        )

        # Mock AWS Identity Store responses
        identity_center_client = MagicMock()
        identity_center_client.create_group.return_value = {'GroupId': 'mocked_group_id'}
        identity_center_client.create_user.return_value = {'UserId': 'mocked_user_id'}

        event = {"dry_run": False}
        context = None

        response = lambda_handler(event, context)

        self.assertEqual(response['statusCode'], 200)
        self.assertEqual(identity_center_client.create_group.call_count, 2)
        self.assertEqual(identity_center_client.create_user.call_count, 2)
        identity_center_client.create_group_membership.assert_called()

    @mock_aws
    @requests_mock.Mocker()
    def test_lambda_handler_add_existing_user(self, mock_requests):
        # Mock Azure token response
        mock_requests.post(
            'https://login.microsoftonline.com/mock_tenant_id/oauth2/v2.0/token',
            json={'access_token': 'mocked_access_token'}
        )

        # Mock Azure group retrieval
        mock_requests.get(
            'https://graph.microsoft.com/v1.0/groups',
            json={'value': [{'id': 'group1', 'displayName': 'entraid-aws-identitycenter-group1'}]}
        )

        # Mock Azure group members
        mock_requests.get(
            'https://graph.microsoft.com/v1.0/groups/group1/members',
            json={'value': [{'userPrincipalName': 'user1@example.com', 'givenName': 'User', 'surname': 'One'}]}
        )

        # Mock AWS Identity Store responses
        identity_center_client = MagicMock()
        identity_center_client.list_group_memberships.return_value = {
            'GroupMemberships': [{'MemberId': {'UserId': 'mocked_user_id'}}]
        }
        identity_center_client.describe_user.return_value = {'UserName': 'user1@example.com'}

        event = {"dry_run": False}
        context = None

        response = lambda_handler(event, context)

        self.assertEqual(response['statusCode'], 200)
        identity_center_client.create_group_membership.assert_not_called()

    @mock_aws
    @requests_mock.Mocker()
    def test_lambda_handler_delete_orphaned_user(self, mock_requests):
        # Mock Azure token response
        mock_requests.post(
            'https://login.microsoftonline.com/mock_tenant_id/oauth2/v2.0/token',
            json={'access_token': 'mocked_access_token'}
        )

        # Mock Azure group retrieval (no groups)
        mock_requests.get(
            'https://graph.microsoft.com/v1.0/groups',
            json={'value': []}  # No groups returned
        )

        # Mock AWS Identity Store responses
        identity_center_client = MagicMock()
        identity_center_client.list_group_memberships.return_value = {'GroupMemberships': []}
        identity_center_client.describe_user.return_value = {
            'UserName': 'user1@example.com',
            'Emails': [{'Type': 'EntraId', 'Primary': True}]
        }

        event = {"dry_run": False}
        context = None

        response = lambda_handler(event, context)

        self.assertEqual(response['statusCode'], 200)
        identity_center_client.delete_user.assert_called_once()

    @mock_aws
    @requests_mock.Mocker()
    def test_lambda_handler_no_changes_needed(self, mock_requests):
        # Mock Azure token response
        mock_requests.post(
            'https://login.microsoftonline.com/mock_tenant_id/oauth2/v2.0/token',
            json={'access_token': 'mocked_access_token'}
        )

        # Mock Azure group retrieval
        mock_requests.get(
            'https://graph.microsoft.com/v1.0/groups',
            json={'value': [{'id': 'group1', 'displayName': 'entraid-aws-identitycenter-group1'}]}
        )

        # Mock Azure group members
        mock_requests.get(
            'https://graph.microsoft.com/v1.0/groups/group1/members',
            json={'value': [{'userPrincipalName': 'user1@example.com', 'givenName': 'User', 'surname': 'One'}]}
        )

        # Mock AWS Identity Store responses
        identity_center_client = MagicMock()
        identity_center_client.list_group_memberships.return_value = {
            'GroupMemberships': [{'MemberId': {'UserId': 'mocked_user_id'}}]
        }
        identity_center_client.describe_user.return_value = {'UserName': 'user1@example.com'}

        event = {"dry_run": False}
        context = None

        response = lambda_handler(event, context)

        self.assertEqual(response['statusCode'], 200)
        identity_center_client.create_group_membership.assert_not_called()
        identity_center_client.delete_group_membership.assert_not_called()

    @mock_aws
    @requests_mock.Mocker()
    def test_lambda_handler_azure_api_failure(self, mock_requests):
        # Mock Azure token response
        mock_requests.post(
            'https://login.microsoftonline.com/mock_tenant_id/oauth2/v2.0/token',
            json={'access_token': 'mocked_access_token'}
        )

        # Mock Azure group retrieval with a failure
        mock_requests.get(
            'https://graph.microsoft.com/v1.0/groups',
            status_code=500,  # Internal Server Error
            text="Internal Server Error"
        )

        event = {"dry_run": False}
        context = None

        response = lambda_handler(event, context)

        self.assertEqual(response['statusCode'], 500)
        self.assertIn('error', response['body'])

    @mock_aws
    @requests_mock.Mocker()
    def test_lambda_handler_aws_api_failure(self, mock_requests):
        # Mock Azure token response
        mock_requests.post(
            'https://login.microsoftonline.com/mock_tenant_id/oauth2/v2.0/token',
            json={'access_token': 'mocked_access_token'}
        )

        # Mock Azure group retrieval
        mock_requests.get(
            'https://graph.microsoft.com/v1.0/groups',
            json={'value': [{'id': 'group1', 'displayName': 'entraid-aws-identitycenter-group1'}]}
        )

        # Mock Azure group members
        mock_requests.get(
            'https://graph.microsoft.com/v1.0/groups/group1/members',
            json={'value': [{'userPrincipalName': 'user1@example.com', 'givenName': 'User', 'surname': 'One'}]}
        )

        # Mock AWS Identity Store responses with failure
        identity_center_client = MagicMock()
        identity_center_client.create_group.side_effect = Exception('AWS API failure')

        event = {"dry_run": False}
        context = None

        response = lambda_handler(event, context)

        self.assertEqual(response['statusCode'], 500)
        self.assertIn('error', response['body'])

    @mock_aws
    @requests_mock.Mocker()
    def test_lambda_handler_empty_group_sync(self, mock_requests):
        # Mock Azure token response
        mock_requests.post(
            'https://login.microsoftonline.com/mock_tenant_id/oauth2/v2.0/token',
            json={'access_token': 'mocked_access_token'}
        )

        # Mock Azure group retrieval
        mock_requests.get(
            'https://graph.microsoft.com/v1.0/groups',
            json={'value': [{'id': 'group1', 'displayName': 'entraid-aws-identitycenter-group1'}]}
        )

        # Mock Azure group members with no members
        mock_requests.get(
            'https://graph.microsoft.com/v1.0/groups/group1/members',
            json={'value': []}
        )

        # Mock AWS Identity Store responses
        identity_center_client = MagicMock()
        identity_center_client.list_group_memberships.return_value = {
            'GroupMemberships': [{'MemberId': {'UserId': 'mocked_user_id'}}]
        }

        event = {"dry_run": False}
        context = None

        response = lambda_handler(event, context)

        self.assertEqual(response['statusCode'], 200)
        identity_center_client.delete_group_membership.assert_called_once()

if __name__ == '__main__':
    unittest.main()
