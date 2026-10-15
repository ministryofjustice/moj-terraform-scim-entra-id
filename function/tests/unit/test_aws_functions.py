# The Azure credentials must be set in the environment before importing the app
# module, which validates them at import time. pylint: disable=wrong-import-position
import os
import unittest
from unittest.mock import MagicMock

from botocore.exceptions import ClientError

os.environ.setdefault("AZURE_TENANT_ID", "test-tenant")
os.environ.setdefault("AZURE_CLIENT_ID", "test-client")
os.environ.setdefault("AZURE_CLIENT_SECRET", "test-secret")

from function import app  # noqa: E402
from function.app import (  # noqa: E402
    get_group_membership_id,
    get_identity_center_groups_and_relevant_users,
    get_identity_center_user_id_by_username,
    get_identity_center_username,
    get_identity_store_id,
    load_identity_center_users,
)


def _paginator(pages):
    """Build a mock boto3 paginator whose paginate() yields the given pages."""
    paginator = MagicMock()
    paginator.paginate.return_value = iter(pages)
    return paginator


class TestAWSFunctions(unittest.TestCase):
    """
    Unit tests for AWS Identity Center helper functions.
    """

    def setUp(self):
        # Reset module-level caches between tests.
        app.user_cache.clear()
        app.identity_center_users.clear()

    def test_get_identity_store_id(self):
        sso_client = MagicMock()
        sso_client.list_instances.return_value = {
            "Instances": [{"IdentityStoreId": "mocked_identity_store_id"}]
        }

        self.assertEqual(get_identity_store_id(sso_client), "mocked_identity_store_id")

    def test_load_identity_center_users_indexes_and_caches(self):
        client = MagicMock()
        client.get_paginator.return_value = _paginator(
            [
                {
                    "Users": [
                        {"UserId": "id1", "UserName": "User1@Justice.gov.uk"},
                        {"UserId": "id2"},  # no UserName - skipped
                    ]
                }
            ]
        )

        result = load_identity_center_users(client, "store")
        # Keyed by lowercase username, preserving original casing in the value.
        self.assertEqual(
            result["user1@justice.gov.uk"],
            {"UserId": "id1", "UserName": "User1@Justice.gov.uk"},
        )
        # The user with no UserName is skipped, leaving a single entry.
        self.assertEqual(len(result), 1)

        # A second call returns the cached index without re-paginating.
        client.get_paginator.reset_mock()
        load_identity_center_users(client, "store")
        client.get_paginator.assert_not_called()

    def test_get_identity_center_username_existing_user(self):
        client = MagicMock()
        client.describe_user.return_value = {"UserName": "mocked_username"}

        username = get_identity_center_username(client, "store", "user_id")
        self.assertEqual(username, "mocked_username")
        # Result is cached.
        self.assertEqual(app.user_cache["user_id"], "mocked_username")

    def test_get_identity_center_username_served_from_cache(self):
        client = MagicMock()
        app.user_cache["user_id"] = "cached_username"

        username = get_identity_center_username(client, "store", "user_id")
        self.assertEqual(username, "cached_username")
        client.describe_user.assert_not_called()

    def test_get_identity_center_username_no_username_not_cached(self):
        client = MagicMock()
        client.describe_user.return_value = {}

        username = get_identity_center_username(client, "store", "user_id")
        self.assertIsNone(username)
        self.assertNotIn("user_id", app.user_cache)

    def test_get_identity_center_username_client_error(self):
        client = MagicMock()
        client.describe_user.side_effect = ClientError(
            {"Error": {"Code": "ResourceNotFoundException", "Message": "nope"}},
            "DescribeUser",
        )

        username = get_identity_center_username(client, "store", "nonexistent")
        self.assertIsNone(username)

    def test_get_identity_center_user_id_by_username_found(self):
        client = MagicMock()
        client.get_paginator.return_value = _paginator(
            [{"Users": [{"UserId": "id1", "UserName": "User1@justice.gov.uk"}]}]
        )

        # Lookup is case-insensitive.
        user_id = get_identity_center_user_id_by_username(
            client, "store", "USER1@JUSTICE.GOV.UK"
        )
        self.assertEqual(user_id, "id1")

    def test_get_identity_center_user_id_by_username_not_found(self):
        client = MagicMock()
        client.get_paginator.return_value = _paginator([{"Users": []}])

        user_id = get_identity_center_user_id_by_username(
            client, "store", "missing@justice.gov.uk"
        )
        self.assertIsNone(user_id)

    def test_get_group_membership_id_existing(self):
        client = MagicMock()
        client.get_paginator.return_value = _paginator(
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

        membership_id = get_group_membership_id(
            client, "store", "group_id", "mocked_user_id"
        )
        self.assertEqual(membership_id, "mocked_membership_id")

    def test_get_group_membership_id_nonexistent(self):
        client = MagicMock()
        client.get_paginator.return_value = _paginator([{"GroupMemberships": []}])

        membership_id = get_group_membership_id(
            client, "store", "group_id", "nonexistent"
        )
        self.assertIsNone(membership_id)

    def test_get_group_membership_id_client_error(self):
        client = MagicMock()
        client.get_paginator.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "no"}},
            "ListGroupMemberships",
        )

        membership_id = get_group_membership_id(client, "store", "group_id", "user_id")
        self.assertIsNone(membership_id)

    def test_get_identity_center_groups_and_relevant_users(self):
        client = MagicMock()

        def get_paginator(name):
            if name == "list_groups":
                return _paginator(
                    [
                        {
                            "Groups": [
                                {
                                    "GroupId": "g1",
                                    "DisplayName": "azure-aws-sso-group1",
                                },
                                {
                                    "GroupId": "gi",
                                    "DisplayName": "azure-aws-sso-analytical-platform-qs-readers",
                                },
                                {
                                    "GroupId": "gx",
                                    "DisplayName": "unrelated-group",
                                },
                            ]
                        }
                    ]
                )
            if name == "list_group_memberships":
                return _paginator(
                    [{"GroupMemberships": [{"MemberId": {"UserId": "u1"}}]}]
                )
            return _paginator([])

        client.get_paginator.side_effect = get_paginator
        client.describe_user.return_value = {"UserName": "user1@justice.gov.uk"}

        groups, relevant_users = get_identity_center_groups_and_relevant_users(
            client, "store", "azure-aws-sso-"
        )

        # Prefix mismatch and ignored group are both excluded.
        self.assertEqual(list(groups.keys()), ["azure-aws-sso-group1"])
        self.assertEqual(
            groups["azure-aws-sso-group1"]["Members"], {"user1@justice.gov.uk"}
        )
        self.assertEqual(relevant_users, {"u1"})

    def test_get_identity_center_groups_skips_membership_with_no_username(self):
        client = MagicMock()

        def get_paginator(name):
            if name == "list_groups":
                return _paginator(
                    [
                        {
                            "Groups": [
                                {"GroupId": "g1", "DisplayName": "azure-aws-sso-group1"}
                            ]
                        }
                    ]
                )
            return _paginator([{"GroupMemberships": [{"MemberId": {"UserId": "u1"}}]}])

        client.get_paginator.side_effect = get_paginator
        # describe_user returns no UserName, so the member is skipped.
        client.describe_user.return_value = {}

        groups, relevant_users = get_identity_center_groups_and_relevant_users(
            client, "store", "azure-aws-sso-"
        )
        self.assertEqual(groups["azure-aws-sso-group1"]["Members"], set())
        self.assertEqual(relevant_users, set())

    def test_get_identity_center_groups_no_prefix_returns_all(self):
        client = MagicMock()

        def get_paginator(name):
            if name == "list_groups":
                return _paginator(
                    [{"Groups": [{"GroupId": "gx", "DisplayName": "any-group"}]}]
                )
            return _paginator([{"GroupMemberships": []}])

        client.get_paginator.side_effect = get_paginator

        groups, _ = get_identity_center_groups_and_relevant_users(client, "store")
        self.assertIn("any-group", groups)

    def test_get_identity_center_groups_client_error_is_raised(self):
        client = MagicMock()
        client.get_paginator.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "no"}}, "ListGroups"
        )

        with self.assertRaises(ClientError):
            get_identity_center_groups_and_relevant_users(client, "store", "prefix")


if __name__ == "__main__":
    unittest.main()
