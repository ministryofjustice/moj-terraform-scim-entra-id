import os
import unittest
from unittest.mock import MagicMock, patch

import requests_mock
from moto import mock_aws

from function.app import lambda_handler


class TestLambdaFunction(unittest.TestCase):
    """
    Unit tests for the AWS Lambda function handling Azure AD and AWS Identity Center integration.

    This test suite mocks various AWS and Azure services to simulate scenarios where users and groups
    are synchronized between Azure AD and AWS Identity Center. It verifies the correct execution
    of the lambda function logic, including user deletion, group deletion, and no-op scenarios.
    """

    def setUp(self):
        self.mock_tenant_id = os.environ.get("AZURE_TENANT_ID", "mock_tenant_id")
        self.mock_access_token_url = (
            f"https://login.microsoftonline.com/{self.mock_tenant_id}/oauth2/v2.0/token"
        )
        self.mock_identity_store_id = "mocked_identity_store_id"
        self.username_to_user_id = {
            "user1@example.com": "user1@example.com_user1_mock_id",
            "admin1@example.com": "admin1@example.com_mock_id",
            "extra_user@example.com": "extra_user@example.com_mock_id",
        }
        self.user_id_to_username = {v: k for k, v in self.username_to_user_id.items()}

    @mock_aws
    @requests_mock.Mocker()
    def test_lambda_handler_remove_user(self, mock_requests):
        # Mock Azure token response
        mock_requests.post(
            self.mock_access_token_url, json={"access_token": "mocked_access_token"}
        )

        # Mock Azure group retrieval
        mock_requests.get(
            "https://graph.microsoft.com/v1.0/groups",
            json={"value": [{"id": "group1", "displayName": "azure-aws-sso-group1"}]},
        )

        # Mock Azure group members (users that should remain in the group)
        mock_requests.get(
            "https://graph.microsoft.com/v1.0/groups/group1/members",
            json={
                "value": [
                    {
                        "userPrincipalName": "user1@example.com",
                        "givenName": "User",
                        "surname": "One",
                    }
                ]
            },
        )

        # Mock Azure group owners (users that should remain in the group)
        mock_requests.get(
            "https://graph.microsoft.com/v1.0/groups/group1/owners",
            json={
                "value": [
                    {
                        "userPrincipalName": "admin1@example.com",
                        "givenName": "Admin",
                        "surname": "One",
                    }
                ]
            },
        )

        # Mock AWS Identity Store responses
        identity_center_client = MagicMock()

        identity_center_client.list_instances.return_value = {
            "Instances": [{"IdentityStoreId": self.mock_identity_store_id}]
        }
        identity_center_client.create_group.return_value = {
            "GroupId": "mocked_group_id"
        }

        def list_users_side_effect(IdentityStoreId, Filters):
            username = next(
                filter["AttributeValue"]
                for filter in Filters
                if filter["AttributePath"] == "UserName"
            )
            user = [{"UserId": f"{self.username_to_user_id[username]}"}]
            return {"Users": user}

        # Mock the list_users to return existing users
        identity_center_client.list_users.side_effect = list_users_side_effect

        # Mocking List Groups
        mock_list_groups_paginator = MagicMock()

        # Mock groups to return in paginate call for list_groups paginator
        mock_groups = [
            {
                "Groups": [
                    {
                        "GroupId": "azure-aws-sso-group1",
                        "DisplayName": "azure-aws-sso-group1",
                    }
                ]
            },
            {
                "Groups": [
                    {
                        "GroupId": "azure-aws-sso-group2",
                        "DisplayName": "azure-aws-sso-group2",
                    }
                ]
            },
            {
                "Groups": [
                    {"GroupId": "some-random-group", "DisplayName": "some-random-group"}
                ]
            },
        ]
        # Set the paginate method to return the mock groups
        mock_list_groups_paginator.paginate.return_value = mock_groups

        # Mocking List Group Memberships
        mock_list_group_memberships_paginator = MagicMock()

        # Mock paginator data for group memberships
        mock_ic_group_membership = [
            {
                "GroupMemberships": [
                    {
                        "MemberId": {
                            "UserId": self.username_to_user_id["user1@example.com"]
                        },
                        "MembershipId": "membership1",
                    },
                    {
                        "MemberId": {
                            "UserId": self.username_to_user_id["admin1@example.com"]
                        },
                        "MembershipId": "membership1",
                    },
                    {
                        "MemberId": {
                            "UserId": self.username_to_user_id["extra_user@example.com"]
                        },
                        "MembershipId": "membership3",
                    },
                ]
            }
        ]
        mock_list_group_memberships_paginator.paginate.return_value = (
            mock_ic_group_membership
        )

        # Side effect function for get_paginator to mock only the list_groups paginator
        def get_paginator_side_effect(paginator_name):
            if paginator_name == "list_groups":
                return mock_list_groups_paginator
            if paginator_name == "list_group_memberships":
                return mock_list_group_memberships_paginator
            return MagicMock()

        # Assign the side effect to the mock's get_paginator method
        identity_center_client.get_paginator.side_effect = get_paginator_side_effect
        # Mock Describe User

        def describe_user_side_effect(IdentityStoreId, UserId):
            if UserId in self.user_id_to_username:
                return {
                    "UserName": self.user_id_to_username[UserId],
                    "Emails": [
                        {
                            "Value": self.user_id_to_username[UserId],
                            "Type": "EntraId",
                            "Primary": True,
                        }
                    ],
                }
            return None

        identity_center_client.describe_user.side_effect = describe_user_side_effect

        # Mock get_group_membership_id
        identity_center_client.get_group_membership_id.return_value = (
            "mocked_membership_id"
        )

        event = {"dry_run": False}
        context = None

        with patch("boto3.client", return_value=identity_center_client):
            response = lambda_handler(event, context)

        print("\n" + "=" * 100 + "\n")

        # Lambda successfully executed
        self.assertEqual(response["statusCode"], 200)
        print("Assertion Passed: Lambda successfully executed")

        # One user ['extra_user@example.com'] is deleted from group ['azure-aws-sso-group1']
        identity_center_client.delete_group_membership.assert_called_once_with(
            IdentityStoreId=self.mock_identity_store_id, MembershipId="membership3"
        )
        print(
            "Assertion Passed: One user ['extra_user@example.com'] is deleted"
            + "from Identity Center group ['azure-aws-sso-group1']"
        )

        # One user ['extra_user@example.com'] is deleted
        identity_center_client.delete_user.assert_called_once_with(
            IdentityStoreId=self.mock_identity_store_id,
            UserId=self.username_to_user_id["extra_user@example.com"],
        )
        print(
            "Assertion Passed: One user ['extra_user@example.com'] is deleted from Identity Center"
        )

        # One group ['azure-aws-sso-group2'] is deleted
        identity_center_client.delete_group.assert_called_once_with(
            IdentityStoreId=self.mock_identity_store_id, GroupId="azure-aws-sso-group2"
        )

        print(
            "Assertion Passed: One group ['azure-aws-sso-group2'] is deleted from Identity Center"
        )
        # No users are created
        identity_center_client.create_user.assert_not_called()

        print("Assertion Passed: No users are created in Identity Center")

        # No users are added to groups
        identity_center_client.create_group_membership.assert_not_called()

        print("Assertion Passed: No users are added to groups in Identity Center")
        print("\n" + "=" * 100)


if __name__ == "__main__":
    unittest.main()
