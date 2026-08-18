# Credentials must be set before importing the app module, which validates them
# at import time. pylint: disable=wrong-import-position
import os
import unittest
from unittest.mock import MagicMock, patch

import requests_mock
from botocore.exceptions import ClientError

os.environ.setdefault("AZURE_TENANT_ID", "mock_tenant_id")
os.environ.setdefault("AZURE_CLIENT_ID", "mock_client_id")
os.environ.setdefault("AZURE_CLIENT_SECRET", "mock_client_secret")

from function.app import HOLDING_GROUP_NAME, lambda_handler  # noqa: E402


def _conflict(operation):
    return ClientError(
        {"Error": {"Code": "ConflictException", "Message": "already exists"}},
        operation,
    )


class TestLambdaFunction(unittest.TestCase):
    """
    End-to-end style tests that drive the whole lambda_handler through all four
    sync phases against the real helper functions.

    Azure Graph is stubbed at the HTTP boundary with requests_mock. The Identity
    Center client is a MagicMock configured to behave like a real store: it
    resolves users, paginates groups and memberships, and tracks deletions so a
    user cannot be described (or double-deleted) once removed.
    """

    def setUp(self):
        self.token_url = (
            "https://login.microsoftonline.com/"
            f"{os.environ['AZURE_TENANT_ID']}/oauth2/v2.0/token"
        )
        self.identity_store_id = "mocked_identity_store_id"
        # Created groups get a DisplayName-derived id, so the holding group's id
        # is predictable once the handler creates it.
        self.holding_group_id = f"{HOLDING_GROUP_NAME}_id"
        self.user_id_to_name = {}

    # -- fixtures ------------------------------------------------------------
    def _build_client(
        self,
        *,
        existing_users,
        list_groups_pages,
        memberships_by_group,
        create_group_membership_side_effect=None,
    ):
        """Build a MagicMock Identity Center client from explicit fixtures."""
        self.user_id_to_name = {uid: name for name, uid in existing_users.items()}
        deleted_user_ids = set()

        client = MagicMock()
        client.list_instances.return_value = {
            "Instances": [{"IdentityStoreId": self.identity_store_id}]
        }

        def create_group(*, DisplayName, **_kwargs):  # noqa: N803
            return {"GroupId": f"{DisplayName}_id"}

        client.create_group.side_effect = create_group

        def create_user(*, UserName, **_kwargs):  # noqa: N803
            user_id = f"{UserName}_id"
            self.user_id_to_name[user_id] = UserName
            return {"UserId": user_id}

        client.create_user.side_effect = create_user

        if create_group_membership_side_effect is not None:
            client.create_group_membership.side_effect = (
                create_group_membership_side_effect
            )

        list_users_pages = [
            {
                "Users": [
                    {"UserId": uid, "UserName": name}
                    for name, uid in existing_users.items()
                ]
            }
        ]

        def list_group_memberships_paginate(*, GroupId, **_kwargs):  # noqa: N803
            return iter([{"GroupMemberships": memberships_by_group.get(GroupId, [])}])

        paginators = {
            "list_groups": lambda **_kw: iter(list_groups_pages),
            "list_group_memberships": list_group_memberships_paginate,
            "list_users": lambda **_kw: iter(list_users_pages),
        }

        def get_paginator(name):
            paginator = MagicMock()
            paginator.paginate.side_effect = paginators[name]
            return paginator

        client.get_paginator.side_effect = get_paginator

        def describe_user(*, UserId, **_kwargs):  # noqa: N803
            if UserId in deleted_user_ids:
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
            deleted_user_ids.add(UserId)

        client.describe_user.side_effect = describe_user
        client.delete_user.side_effect = delete_user
        return client

    def _stub_token(self, mock_requests):
        mock_requests.post(self.token_url, json={"access_token": "mocked_access_token"})

    def _stub_group(self, mock_requests, *, graph_id, members, owners=()):
        base = f"https://graph.microsoft.com/v1.0/groups/{graph_id}"
        mock_requests.get(f"{base}/members", json={"value": list(members)})
        mock_requests.get(f"{base}/owners", json={"value": list(owners)})

    @staticmethod
    def _member(upn, given="Given", surname="Surname"):
        return {"userPrincipalName": upn, "givenName": given, "surname": surname}

    def _run(self, client, event):
        with patch("boto3.client", return_value=client):
            return lambda_handler(event, None)

    # -- scenarios -----------------------------------------------------------
    @requests_mock.Mocker()
    def test_prunes_stale_user_and_obsolete_group(self, mock_requests):
        """A user and a group that vanished from Azure are removed from AWS."""
        self._stub_token(mock_requests)
        mock_requests.get(
            "https://graph.microsoft.com/v1.0/groups",
            json={"value": [{"id": "group1", "displayName": "azure-aws-sso-group1"}]},
        )
        # user1 stays; extra_user is intentionally absent from Azure.
        self._stub_group(
            mock_requests,
            graph_id="group1",
            members=[self._member("user1@justice.gov.uk")],
            owners=[self._member("admin1@justice.gov.uk")],
        )

        client = self._build_client(
            existing_users={
                "user1@justice.gov.uk": "user1_id",
                "admin1@justice.gov.uk": "admin1_id",
                "extra_user@justice.gov.uk": "extra_user_id",
            },
            list_groups_pages=[
                {
                    "Groups": [
                        {"GroupId": "grp1_id", "DisplayName": "azure-aws-sso-group1"},
                        {"GroupId": "grp2_id", "DisplayName": "azure-aws-sso-group2"},
                        {"GroupId": "other_id", "DisplayName": "some-random-group"},
                    ]
                }
            ],
            memberships_by_group={
                "grp1_id": [
                    {"MemberId": {"UserId": "user1_id"}, "MembershipId": "m_user1_g1"},
                    {
                        "MemberId": {"UserId": "admin1_id"},
                        "MembershipId": "m_admin1_g1",
                    },
                    {
                        "MemberId": {"UserId": "extra_user_id"},
                        "MembershipId": "m_extra_g1",
                    },
                ],
                "grp2_id": [],
                self.holding_group_id: [
                    {
                        "MemberId": {"UserId": "extra_user_id"},
                        "MembershipId": "m_extra_hold",
                    }
                ],
            },
        )

        response = self._run(client, {"dry_run": False})
        self.assertEqual(response["statusCode"], 200)

        # Obsolete group deleted.
        client.delete_group.assert_called_once_with(
            IdentityStoreId=self.identity_store_id, GroupId="grp2_id"
        )
        # Stale user removed from group and holding group.
        client.delete_group_membership.assert_any_call(
            IdentityStoreId=self.identity_store_id, MembershipId="m_extra_g1"
        )
        client.delete_group_membership.assert_any_call(
            IdentityStoreId=self.identity_store_id, MembershipId="m_extra_hold"
        )
        # Deleted exactly once - the orphan-cleanup phase must not double-delete
        # because describe_user 404s once the user is gone.
        client.delete_user.assert_called_once_with(
            IdentityStoreId=self.identity_store_id, UserId="extra_user_id"
        )
        client.create_user.assert_not_called()

    @requests_mock.Mocker()
    def test_creates_new_group_user_and_holding_group(self, mock_requests):
        """An empty AWS store is populated from a fresh Azure group."""
        self._stub_token(mock_requests)
        mock_requests.get(
            "https://graph.microsoft.com/v1.0/groups",
            json={"value": [{"id": "groupN", "displayName": "azure-aws-sso-new"}]},
        )
        self._stub_group(
            mock_requests,
            graph_id="groupN",
            members=[self._member("newbie@justice.gov.uk", "New", "Bie")],
        )

        # No existing users and no existing groups in AWS.
        client = self._build_client(
            existing_users={},
            list_groups_pages=[{"Groups": []}],
            memberships_by_group={},
        )

        response = self._run(client, {"dry_run": False})
        self.assertEqual(response["statusCode"], 200)

        # Holding group and the new group are both created.
        created_groups = {
            call.kwargs["DisplayName"] for call in client.create_group.call_args_list
        }
        self.assertEqual(created_groups, {HOLDING_GROUP_NAME, "azure-aws-sso-new"})

        # The new user is created once and added to its group and the holding group.
        client.create_user.assert_called_once()
        self.assertEqual(
            client.create_user.call_args.kwargs["UserName"], "newbie@justice.gov.uk"
        )
        added_to = [
            call.kwargs["GroupId"]
            for call in client.create_group_membership.call_args_list
        ]
        self.assertEqual(set(added_to), {"azure-aws-sso-new_id", self.holding_group_id})
        client.delete_user.assert_not_called()
        client.delete_group.assert_not_called()

    @requests_mock.Mocker()
    def test_membership_conflict_is_handled_gracefully(self, mock_requests):
        """A ConflictException when adding a member does not fail the run."""
        self._stub_token(mock_requests)
        mock_requests.get(
            "https://graph.microsoft.com/v1.0/groups",
            json={"value": [{"id": "group1", "displayName": "azure-aws-sso-group1"}]},
        )
        self._stub_group(
            mock_requests,
            graph_id="group1",
            members=[self._member("user1@justice.gov.uk")],
        )

        # user1 exists but is not yet recorded as a member, so the handler tries
        # to add them - and every add raises ConflictException.
        client = self._build_client(
            existing_users={"user1@justice.gov.uk": "user1_id"},
            list_groups_pages=[
                {
                    "Groups": [
                        {"GroupId": "grp1_id", "DisplayName": "azure-aws-sso-group1"}
                    ]
                }
            ],
            memberships_by_group={"grp1_id": []},
            create_group_membership_side_effect=_conflict("CreateGroupMembership"),
        )

        response = self._run(client, {"dry_run": False})

        # The conflict is swallowed - the run still completes successfully.
        self.assertEqual(response["statusCode"], 200)
        self.assertTrue(client.create_group_membership.called)
        client.delete_user.assert_not_called()

    @requests_mock.Mocker()
    def test_dry_run_makes_no_mutating_calls(self, mock_requests):
        """dry_run=True logs intent but never mutates the store."""
        self._stub_token(mock_requests)
        mock_requests.get(
            "https://graph.microsoft.com/v1.0/groups",
            json={"value": [{"id": "group1", "displayName": "azure-aws-sso-group1"}]},
        )
        self._stub_group(
            mock_requests,
            graph_id="group1",
            members=[self._member("user1@justice.gov.uk")],
        )

        client = self._build_client(
            existing_users={
                "user1@justice.gov.uk": "user1_id",
                "extra_user@justice.gov.uk": "extra_user_id",
            },
            list_groups_pages=[
                {
                    "Groups": [
                        {"GroupId": "grp1_id", "DisplayName": "azure-aws-sso-group1"},
                        {"GroupId": "grp2_id", "DisplayName": "azure-aws-sso-group2"},
                    ]
                }
            ],
            memberships_by_group={
                "grp1_id": [
                    {
                        "MemberId": {"UserId": "extra_user_id"},
                        "MembershipId": "m_extra_g1",
                    }
                ],
                "grp2_id": [],
            },
        )

        # The handler treats dry_run as the string "True" (see lambda_handler),
        # matching how the function is invoked in practice.
        response = self._run(client, {"dry_run": "True"})
        self.assertEqual(response["statusCode"], 200)

        # No mutating API call is made in a dry run.
        client.create_group.assert_not_called()
        client.create_user.assert_not_called()
        client.create_group_membership.assert_not_called()
        client.delete_group.assert_not_called()
        client.delete_group_membership.assert_not_called()
        client.delete_user.assert_not_called()


if __name__ == "__main__":
    unittest.main()
