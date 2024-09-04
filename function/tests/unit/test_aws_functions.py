import unittest
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError

from function.app import (
    get_group_membership_id,
    get_identity_center_username,
    get_identity_store_id,
)


class TestAWSFunctions(unittest.TestCase):
    @patch("function.app.boto3.client")
    def test_get_identity_store_id(self, mock_boto_client):
        sso_client = MagicMock()
        mock_boto_client.return_value = sso_client

        sso_client.list_instances.return_value = {
            "Instances": [{"IdentityStoreId": "mocked_identity_store_id"}]
        }

        identity_store_id = get_identity_store_id(sso_client)
        self.assertEqual(identity_store_id, "mocked_identity_store_id")

    @patch("function.app.boto3.client")
    def test_get_identity_center_username_existing_user(self, mock_boto_client):
        identity_center_client = MagicMock()
        mock_boto_client.return_value = identity_center_client

        mock_response = MagicMock()
        mock_response.get.return_value = "mocked_username"
        identity_center_client.describe_user.return_value = mock_response

        username = get_identity_center_username(
            identity_center_client, "mocked_identity_store_id", "mocked_user_id"
        )
        self.assertEqual(username, "mocked_username")

    @patch("function.app.boto3.client")
    def test_get_identity_center_username_nonexistent_user(self, mock_boto_client):
        identity_center_client = MagicMock()
        mock_boto_client.return_value = identity_center_client

        identity_center_client.describe_user.side_effect = ClientError(
            {
                "Error": {
                    "Code": "ResourceNotFoundException",
                    "Message": "User does not exist",
                }
            },
            "DescribeUser",
        )

        username = get_identity_center_username(
            identity_center_client, "mocked_identity_store_id", "nonexistent_user_id"
        )
        self.assertIsNone(username)

    @patch("function.app.boto3.client")
    def test_get_group_membership_id_existing(self, mock_boto_client):
        identity_center_client = MagicMock()
        mock_boto_client.return_value = identity_center_client

        mock_page = MagicMock()
        mock_page.paginate.return_value = [
            {
                "GroupMemberships": [
                    {
                        "MembershipId": "mocked_membership_id",
                        "MemberId": {"UserId": "mocked_user_id"},
                    }
                ]
            }
        ]
        identity_center_client.get_paginator.return_value = mock_page

        membership_id = get_group_membership_id(
            identity_center_client,
            "mocked_identity_store_id",
            "mocked_group_id",
            "mocked_user_id",
        )
        self.assertEqual(membership_id, "mocked_membership_id")

    @patch("function.app.boto3.client")
    def test_get_group_membership_id_nonexistent(self, mock_boto_client):
        identity_center_client = MagicMock()
        mock_boto_client.return_value = identity_center_client

        mock_page = MagicMock()
        mock_page.paginate.return_value = [{"GroupMemberships": []}]
        identity_center_client.get_paginator.return_value = mock_page

        membership_id = get_group_membership_id(
            identity_center_client,
            "mocked_identity_store_id",
            "mocked_group_id",
            "nonexistent_user_id",
        )
        self.assertIsNone(membership_id)


if __name__ == "__main__":
    unittest.main()
