# Credentials must be set before importing the app module, which validates them
# at import time. pylint: disable=wrong-import-position
import os
import unittest

import boto3
import requests_mock
from moto import mock_aws

os.environ.setdefault("AZURE_TENANT_ID", "mock_tenant_id")
os.environ.setdefault("AZURE_CLIENT_ID", "mock_client_id")
os.environ.setdefault("AZURE_CLIENT_SECRET", "mock_client_secret")
# moto needs credentials and a region to sign requests, even though nothing
# leaves the process.
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "eu-west-2")

from function.app import HOLDING_GROUP_NAME, lambda_handler  # noqa: E402

REGION = "eu-west-2"


class TestLambdaFunction(unittest.TestCase):
    """
    End-to-end tests that drive the whole lambda_handler against a moto-backed
    AWS Identity Center.

    moto simulates the identitystore and sso-admin services in-process, so the
    handler's own boto3 clients are intercepted with no patching. Azure Graph is
    stubbed at the HTTP boundary with requests_mock. Assertions inspect the real
    (simulated) store state after the run rather than mock call records.
    """

    TOKEN_URL = (
        "https://login.microsoftonline.com/"
        f"{os.environ['AZURE_TENANT_ID']}/oauth2/v2.0/token"
    )

    # -- moto store helpers --------------------------------------------------
    @staticmethod
    def _store_id():
        sso = boto3.client("sso-admin", region_name=REGION)
        return sso.list_instances()["Instances"][0]["IdentityStoreId"]

    @staticmethod
    def _create_user(ids, store, username):
        return ids.create_user(
            IdentityStoreId=store,
            UserName=username,
            DisplayName=username,
            Name={"FamilyName": username, "GivenName": username},
            Emails=[{"Value": username, "Type": "EntraId", "Primary": True}],
        )["UserId"]

    @staticmethod
    def _groups_by_name(ids, store):
        result = {}
        for page in ids.get_paginator("list_groups").paginate(IdentityStoreId=store):
            for group in page["Groups"]:
                result[group["DisplayName"]] = group["GroupId"]
        return result

    @staticmethod
    def _usernames(ids, store):
        result = set()
        for page in ids.get_paginator("list_users").paginate(IdentityStoreId=store):
            for user in page["Users"]:
                result.add(user["UserName"])
        return result

    @staticmethod
    def _member_ids(ids, store, group_id):
        result = set()
        for page in ids.get_paginator("list_group_memberships").paginate(
            IdentityStoreId=store, GroupId=group_id
        ):
            for membership in page["GroupMemberships"]:
                result.add(membership["MemberId"]["UserId"])
        return result

    # -- Azure Graph stubs ---------------------------------------------------
    def _stub_token(self, mock_requests):
        mock_requests.post(self.TOKEN_URL, json={"access_token": "mocked_access_token"})

    @staticmethod
    def _stub_groups(mock_requests, groups):
        mock_requests.get(
            "https://graph.microsoft.com/v1.0/groups", json={"value": groups}
        )

    @staticmethod
    def _stub_group_members(mock_requests, graph_id, members, owners=()):
        base = f"https://graph.microsoft.com/v1.0/groups/{graph_id}"
        mock_requests.get(f"{base}/members", json={"value": list(members)})
        mock_requests.get(f"{base}/owners", json={"value": list(owners)})

    @staticmethod
    def _member(upn, given="Given", surname="Surname"):
        return {"userPrincipalName": upn, "givenName": given, "surname": surname}

    # -- scenarios -----------------------------------------------------------
    @mock_aws
    @requests_mock.Mocker()
    def test_prunes_stale_user_and_obsolete_group(self, mock_requests):
        """A user and a group that vanished from Azure are removed from AWS."""
        ids = boto3.client("identitystore", region_name=REGION)
        store = self._store_id()

        # Seed AWS state: two prefixed groups, the holding group, and an
        # unrelated group. group1 and the holding group contain a stale user.
        grp1 = ids.create_group(
            IdentityStoreId=store, DisplayName="azure-aws-sso-group1"
        )["GroupId"]
        ids.create_group(IdentityStoreId=store, DisplayName="azure-aws-sso-group2")
        holding = ids.create_group(
            IdentityStoreId=store, DisplayName=HOLDING_GROUP_NAME
        )["GroupId"]
        other = ids.create_group(
            IdentityStoreId=store, DisplayName="some-random-group"
        )["GroupId"]

        user1 = self._create_user(ids, store, "user1@justice.gov.uk")
        admin1 = self._create_user(ids, store, "admin1@justice.gov.uk")
        extra = self._create_user(ids, store, "extra_user@justice.gov.uk")
        for user in (user1, admin1, extra):
            ids.create_group_membership(
                IdentityStoreId=store, GroupId=grp1, MemberId={"UserId": user}
            )
            ids.create_group_membership(
                IdentityStoreId=store, GroupId=holding, MemberId={"UserId": user}
            )

        # Azure now only lists group1 with user1 (member) and admin1 (owner).
        self._stub_token(mock_requests)
        self._stub_groups(
            mock_requests,
            [{"id": "group1", "displayName": "azure-aws-sso-group1"}],
        )
        self._stub_group_members(
            mock_requests,
            "group1",
            members=[self._member("user1@justice.gov.uk")],
            owners=[self._member("admin1@justice.gov.uk")],
        )

        response = lambda_handler({"dry_run": False}, None)
        self.assertEqual(response["statusCode"], 200)

        groups = self._groups_by_name(ids, store)
        # Obsolete group deleted; holding and unrelated groups survive.
        self.assertNotIn("azure-aws-sso-group2", groups)
        self.assertIn(HOLDING_GROUP_NAME, groups)
        self.assertIn("some-random-group", groups)

        # Stale user removed from group1 and the holding group, and deleted.
        self.assertEqual(self._member_ids(ids, store, grp1), {user1, admin1})
        self.assertEqual(self._member_ids(ids, store, holding), {user1, admin1})
        self.assertNotIn("extra_user@justice.gov.uk", self._usernames(ids, store))
        # The unrelated group is left completely untouched.
        self.assertEqual(self._member_ids(ids, store, other), set())

    @mock_aws
    @requests_mock.Mocker()
    def test_creates_new_group_user_and_holding_group(self, mock_requests):
        """An empty AWS store is populated from a fresh Azure group."""
        ids = boto3.client("identitystore", region_name=REGION)
        store = self._store_id()

        self._stub_token(mock_requests)
        self._stub_groups(
            mock_requests,
            [{"id": "groupN", "displayName": "azure-aws-sso-new"}],
        )
        self._stub_group_members(
            mock_requests,
            "groupN",
            members=[self._member("newbie@justice.gov.uk", "New", "Bie")],
        )

        response = lambda_handler({"dry_run": False}, None)
        self.assertEqual(response["statusCode"], 200)

        groups = self._groups_by_name(ids, store)
        # Both the holding group and the new group were created.
        self.assertIn(HOLDING_GROUP_NAME, groups)
        self.assertIn("azure-aws-sso-new", groups)

        # The new user exists and is a member of its group and the holding group.
        usernames = self._usernames(ids, store)
        self.assertIn("newbie@justice.gov.uk", usernames)
        new_group_members = self._member_ids(ids, store, groups["azure-aws-sso-new"])
        holding_members = self._member_ids(ids, store, groups[HOLDING_GROUP_NAME])
        self.assertEqual(len(new_group_members), 1)
        self.assertEqual(new_group_members, holding_members)

    @mock_aws
    @requests_mock.Mocker()
    def test_dry_run_makes_no_changes(self, mock_requests):
        """dry_run=True inspects Azure but never mutates the store."""
        ids = boto3.client("identitystore", region_name=REGION)
        store = self._store_id()

        # Seed a store that a live run would change (obsolete group + stale user).
        grp1 = ids.create_group(
            IdentityStoreId=store, DisplayName="azure-aws-sso-group1"
        )["GroupId"]
        ids.create_group(IdentityStoreId=store, DisplayName="azure-aws-sso-group2")
        extra = self._create_user(ids, store, "extra_user@justice.gov.uk")
        ids.create_group_membership(
            IdentityStoreId=store, GroupId=grp1, MemberId={"UserId": extra}
        )

        # Azure lists group1 with a brand-new user - a live run would create the
        # user, create the holding group, and prune extra_user and group2.
        self._stub_token(mock_requests)
        self._stub_groups(
            mock_requests,
            [{"id": "group1", "displayName": "azure-aws-sso-group1"}],
        )
        self._stub_group_members(
            mock_requests,
            "group1",
            members=[self._member("user1@justice.gov.uk")],
        )

        before_groups = self._groups_by_name(ids, store)
        before_users = self._usernames(ids, store)
        before_members = self._member_ids(ids, store, grp1)

        # The handler treats dry_run as the string "True" (see lambda_handler),
        # matching how the function is invoked in practice.
        response = lambda_handler({"dry_run": "True"}, None)
        self.assertEqual(response["statusCode"], 200)

        # Nothing in the store changed.
        self.assertEqual(self._groups_by_name(ids, store), before_groups)
        self.assertEqual(self._usernames(ids, store), before_users)
        self.assertEqual(self._member_ids(ids, store, grp1), before_members)
        self.assertNotIn(HOLDING_GROUP_NAME, before_groups)


if __name__ == "__main__":
    unittest.main()
