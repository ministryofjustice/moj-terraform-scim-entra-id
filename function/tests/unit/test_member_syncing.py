import unittest
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError

from function.app import (
    delete_orphaned_aws_users,
    remove_members_not_in_azure_groups,
    sync_group_members,
)


class TestMemberSync(unittest.TestCase):
    @patch("function.app.get_identity_center_user_id_by_username")
    @patch("function.app.boto3.client")
    def test_sync_group_members_user_already_exists(
        self, mock_boto_client, mock_get_user_id
    ):
        identity_center_client = MagicMock()
        mock_boto_client.return_value = identity_center_client

        # Mock to simulate user already exists
        mock_get_user_id.return_value = "existing_user_id"

        group_info = {"GroupId": "mocked_group_id", "Members": set()}
        members = [
            {
                "userPrincipalName": "user1@example.com",
                "givenName": "User",
                "surname": "One",
            }
        ]

        sync_group_members(
            identity_center_client,
            "mocked_identity_store_id",
            group_info,
            members,
            "mocked_group_name",
            dry_run=False,
        )

        # Ensure create_user was not called
        identity_center_client.create_user.assert_not_called()
        identity_center_client.create_group_membership.assert_called_once()

    @patch("function.app.get_identity_center_user_id_by_username")
    @patch("function.app.boto3.client")
    def test_sync_group_members_user_does_not_exist(
        self, mock_boto_client, mock_get_user_id
    ):
        identity_center_client = MagicMock()
        mock_boto_client.return_value = identity_center_client

        # Mock to simulate user does not exist initially
        mock_get_user_id.return_value = None
        identity_center_client.create_user.return_value = {"UserId": "mocked_user_id"}

        group_info = {"GroupId": "mocked_group_id", "Members": set()}
        members = [
            {
                "userPrincipalName": "user1@example.com",
                "givenName": "User",
                "surname": "One",
            }
        ]

        sync_group_members(
            identity_center_client,
            "mocked_identity_store_id",
            group_info,
            members,
            "mocked_group_name",
            dry_run=False,
        )

        # Ensure create_user and create_group_membership were called
        identity_center_client.create_user.assert_called_once()
        identity_center_client.create_group_membership.assert_called_once()

    @patch("function.app.get_identity_center_user_id_by_username")
    @patch("function.app.boto3.client")
    def test_sync_group_members_user_does_not_exist_dry_run(
        self, mock_boto_client, mock_get_user_id
    ):
        identity_center_client = MagicMock()
        mock_boto_client.return_value = identity_center_client

        # Mock to simulate user does not exist initially
        mock_get_user_id.return_value = None

        group_info = {"GroupId": "mocked_group_id", "Members": set()}
        members = [
            {
                "userPrincipalName": "user1@example.com",
                "givenName": "User",
                "surname": "One",
            }
        ]

        sync_group_members(
            identity_center_client,
            "mocked_identity_store_id",
            group_info,
            members,
            "mocked_group_name",
            dry_run=True,
        )

        # Ensure create_user and create_group_membership were not called in dry run
        identity_center_client.create_user.assert_not_called()
        identity_center_client.create_group_membership.assert_not_called()

    @patch("function.app.get_identity_center_user_id_by_username")
    @patch("function.app.boto3.client")
    def test_sync_group_members_user_already_in_group(
        self, mock_boto_client, mock_get_user_id
    ):
        identity_center_client = MagicMock()
        mock_boto_client.return_value = identity_center_client

        # Mock to simulate user already exists and is in the group
        mock_get_user_id.return_value = "existing_user_id"

        group_info = {"GroupId": "mocked_group_id", "Members": {"user1@example.com"}}
        members = [
            {
                "userPrincipalName": "user1@example.com",
                "givenName": "User",
                "surname": "One",
            }
        ]

        sync_group_members(
            identity_center_client,
            "mocked_identity_store_id",
            group_info,
            members,
            "mocked_group_name",
            dry_run=False,
        )

        # Ensure create_user and create_group_membership were not called
        identity_center_client.create_user.assert_not_called()
        identity_center_client.create_group_membership.assert_not_called()

    @patch("function.app.get_identity_center_user_id_by_username")
    @patch("function.app.boto3.client")
    def test_sync_group_members_error_handling(
        self, mock_boto_client, mock_get_user_id
    ):
        identity_center_client = MagicMock()
        mock_boto_client.return_value = identity_center_client

        # Mock to simulate user does not exist initially
        mock_get_user_id.return_value = None

        # Simulate error during user creation
        identity_center_client.create_user.side_effect = ClientError(
            {
                "Error": {
                    "Code": "InternalFailure",
                    "Message": "An internal error occurred",
                }
            },
            "CreateUser",
        )

        group_info = {"GroupId": "mocked_group_id", "Members": set()}
        members = [
            {
                "userPrincipalName": "user1@example.com",
                "givenName": "User",
                "surname": "One",
            }
        ]

        with self.assertRaises(ClientError):
            sync_group_members(
                identity_center_client,
                "mocked_identity_store_id",
                group_info,
                members,
                "mocked_group_name",
                dry_run=False,
            )

        # Ensure create_group_membership was not called due to the error
        identity_center_client.create_group_membership.assert_not_called()

    @patch("function.app.get_identity_center_user_id_by_username")
    @patch("function.app.boto3.client")
    def test_remove_obsolete_users(self, mock_boto_client, mock_get_user_id):
        identity_center_client = MagicMock()
        mock_boto_client.return_value = identity_center_client

        # Mock get_paginator to return a mock paginator with a paginate method
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = iter(
            [
                {
                    "GroupMemberships": [
                        {
                            "MembershipId": "mocked_membership_id",
                            "MemberId": {"UserId": "mocked_user_id"},
                        }
                    ]
                }
            ]
        )
        identity_center_client.get_paginator.return_value = mock_paginator

        # Mock that the user exists in AWS Identity Center
        mock_get_user_id.return_value = "mocked_user_id"

        aws_groups = {
            "group1": {"GroupId": "mocked_group_id", "Members": {"user1@example.com"}}
        }
        azure_group_members = {"group1": [{"userPrincipalName": "user2@example.com"}]}

        remove_members_not_in_azure_groups(
            identity_center_client,
            "mocked_identity_store_id",
            aws_groups,
            azure_group_members,
            dry_run=False,
        )

        # Assert that delete_group_membership was called
        identity_center_client.delete_group_membership.assert_called_once_with(
            IdentityStoreId="mocked_identity_store_id",
            MembershipId="mocked_membership_id",
        )

    @patch("function.app.get_identity_center_user_id_by_username")
    @patch("function.app.boto3.client")
    def test_delete_unused_users(self, mock_boto_client, mock_get_user_id):
        identity_center_client = MagicMock()
        mock_boto_client.return_value = identity_center_client

        identity_center_client.describe_user.return_value = {
            "UserName": "user1@example.com",
            "Emails": [
                {"Value": "user1@example.com", "Type": "EntraId", "Primary": True}
            ],
        }

        aws_groups = {"group1": {"Members": set()}}
        relevant_users = {"mocked_user_id"}

        delete_orphaned_aws_users(
            identity_center_client,
            "mocked_identity_store_id",
            aws_groups,
            relevant_users,
            dry_run=False,
        )

        identity_center_client.delete_user.assert_called_once()


if __name__ == "__main__":
    unittest.main()
