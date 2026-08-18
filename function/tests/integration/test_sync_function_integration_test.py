# Credentials must be set before importing the app module, which validates them
# at import time. pylint: disable=wrong-import-position
import os
import unittest
from unittest.mock import MagicMock, patch

import requests_mock
from botocore.exceptions import ClientError
from moto import mock_aws

os.environ.setdefault("AZURE_TENANT_ID", "mock_tenant_id")
os.environ.setdefault("AZURE_CLIENT_ID", "mock_client_id")
os.environ.setdefault("AZURE_CLIENT_SECRET", "mock_client_secret")

from function.app import lambda_handler  # noqa: E402


class TestLambdaFunction(unittest.TestCase):
    """
    End-to-end style test for the Lambda handler.

    Azure Graph is stubbed with requests_mock and the Identity Center client is
    a MagicMock configured to behave like a real store: a user and a group that
    exist in AWS but no longer in Azure should be pruned, while users still
    present in Azure are left untouched.
    """

    def setUp(self):
        self.mock_tenant_id = os.environ["AZURE_TENANT_ID"]
        self.token_url = (
            f"https://login.microsoftonline.com/{self.mock_tenant_id}/oauth2/v2.0/token"
        )
        self.identity_store_id = "mocked_identity_store_id"
        self.holding_group_id = "holding_group_id"

        # Identity Center users, keyed by username.
        self.users = {
            "user1@justice.gov.uk": "user1_id",
            "admin1@justice.gov.uk": "admin1_id",
            "extra_user@justice.gov.uk": "extra_user_id",
        }
        self.user_id_to_name = {v: k for k, v in self.users.items()}
        # Users that have been deleted during the run, so describe_user can 404.
        self.deleted_user_ids = set()

    def _build_client(self):
        client = MagicMock()

        client.list_instances.return_value = {
            "Instances": [{"IdentityStoreId": self.identity_store_id}]
        }
        # The holding group does not exist yet, so it is created during the run.
        client.create_group.return_value = {"GroupId": self.holding_group_id}

        # --- Paginated collections -------------------------------------------
        # AWS groups: two azure-aws-sso groups plus one unrelated group.
        list_groups_pages = [
            {
                "Groups": [
                    {"GroupId": "grp1_id", "DisplayName": "azure-aws-sso-group1"},
                    {"GroupId": "grp2_id", "DisplayName": "azure-aws-sso-group2"},
                    {"GroupId": "other_id", "DisplayName": "some-random-group"},
                ]
            }
        ]

        # Group memberships keyed by GroupId. group1 holds an extra user who is
        # no longer in the Azure group and should be removed.
        memberships_by_group = {
            "grp1_id": [
                {"MemberId": {"UserId": "user1_id"}, "MembershipId": "m_user1_g1"},
                {"MemberId": {"UserId": "admin1_id"}, "MembershipId": "m_admin1_g1"},
                {"MemberId": {"UserId": "extra_user_id"}, "MembershipId": "m_extra_g1"},
            ],
            "grp2_id": [],
            self.holding_group_id: [
                {
                    "MemberId": {"UserId": "extra_user_id"},
                    "MembershipId": "m_extra_hold",
                },
            ],
        }

        # All users, for the list_users index built by load_identity_center_users.
        list_users_pages = [
            {
                "Users": [
                    {"UserId": uid, "UserName": name}
                    for name, uid in self.users.items()
                ]
            }
        ]

        def list_groups_paginate(**_kwargs):
            return iter(list_groups_pages)

        def list_group_memberships_paginate(*, GroupId, **_kwargs):  # noqa: N803
            return iter([{"GroupMemberships": memberships_by_group.get(GroupId, [])}])

        def list_users_paginate(**_kwargs):
            return iter(list_users_pages)

        paginators = {
            "list_groups": list_groups_paginate,
            "list_group_memberships": list_group_memberships_paginate,
            "list_users": list_users_paginate,
        }

        def get_paginator(name):
            paginator = MagicMock()
            paginator.paginate.side_effect = paginators[name]
            return paginator

        client.get_paginator.side_effect = get_paginator

        # --- describe_user / delete_user with deletion tracking --------------
        def describe_user(*, UserId, **_kwargs):  # noqa: N803
            if UserId in self.deleted_user_ids:
                raise ClientError(
                    {
                        "Error": {
                            "Code": "ResourceNotFoundException",
                            "Message": "User does not exist",
                        }
                    },
                    "DescribeUser",
                )
            username = self.user_id_to_name[UserId]
            return {
                "UserName": username,
                "Emails": [{"Value": username, "Type": "EntraId", "Primary": True}],
            }

        def delete_user(*, UserId, **_kwargs):  # noqa: N803
            self.deleted_user_ids.add(UserId)

        client.describe_user.side_effect = describe_user
        client.delete_user.side_effect = delete_user

        return client

    def _stub_azure(self, mock_requests):
        mock_requests.post(self.token_url, json={"access_token": "mocked_access_token"})
        mock_requests.get(
            "https://graph.microsoft.com/v1.0/groups",
            json={"value": [{"id": "group1", "displayName": "azure-aws-sso-group1"}]},
        )
        # user1 remains a member; extra_user is intentionally absent.
        mock_requests.get(
            "https://graph.microsoft.com/v1.0/groups/group1/members",
            json={
                "value": [
                    {
                        "userPrincipalName": "user1@justice.gov.uk",
                        "givenName": "User",
                        "surname": "One",
                    }
                ]
            },
        )
        mock_requests.get(
            "https://graph.microsoft.com/v1.0/groups/group1/owners",
            json={
                "value": [
                    {
                        "userPrincipalName": "admin1@justice.gov.uk",
                        "givenName": "Admin",
                        "surname": "One",
                    }
                ]
            },
        )

    @mock_aws
    @requests_mock.Mocker()
    def test_lambda_handler_prunes_stale_user_and_group(self, mock_requests):
        self._stub_azure(mock_requests)
        client = self._build_client()

        with patch("boto3.client", return_value=client):
            response = lambda_handler({"dry_run": False}, None)

        # Lambda completed successfully.
        self.assertEqual(response["statusCode"], 200)

        # The obsolete group (absent from Azure) is deleted.
        client.delete_group.assert_called_once_with(
            IdentityStoreId=self.identity_store_id, GroupId="grp2_id"
        )

        # The stale user is removed from both the group and the holding group.
        client.delete_group_membership.assert_any_call(
            IdentityStoreId=self.identity_store_id, MembershipId="m_extra_g1"
        )
        client.delete_group_membership.assert_any_call(
            IdentityStoreId=self.identity_store_id, MembershipId="m_extra_hold"
        )

        # The stale user is deleted exactly once (step 4 must not double-delete
        # because describe_user now 404s for the already-deleted user).
        client.delete_user.assert_called_once_with(
            IdentityStoreId=self.identity_store_id, UserId="extra_user_id"
        )

        # Users still present in Azure are added to the holding group, but no
        # new Identity Center users are created.
        client.create_user.assert_not_called()
        holding_adds = [
            call
            for call in client.create_group_membership.call_args_list
            if call.kwargs.get("GroupId") == self.holding_group_id
        ]
        self.assertEqual(len(holding_adds), 2)


if __name__ == "__main__":
    unittest.main()
