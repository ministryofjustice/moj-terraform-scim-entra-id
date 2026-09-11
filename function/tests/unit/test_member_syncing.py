# Credentials must be set before importing the app module, which validates them
# at import time. pylint: disable=wrong-import-position
import os
import unittest
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError, ParamValidationError

os.environ.setdefault("AZURE_TENANT_ID", "test-tenant")
os.environ.setdefault("AZURE_CLIENT_ID", "test-client")
os.environ.setdefault("AZURE_CLIENT_SECRET", "test-secret")

from function import app  # noqa: E402
from function.app import (  # noqa: E402
    HOLDING_GROUP_NAME,
    delete_orphaned_aws_users,
    remove_members_not_in_azure_groups,
    remove_obsolete_groups,
    sync_azure_groups_with_aws,
    sync_group_members,
)


def _member(upn="user1@justice.gov.uk", **extra):
    member = {"userPrincipalName": upn, "givenName": "User", "surname": "One"}
    member.update(extra)
    return member


def _conflict_error(operation):
    return ClientError(
        {"Error": {"Code": "ConflictException", "Message": "exists"}}, operation
    )


def _aws_group(members=(), group_id="group_id", name="azure-aws-sso-group1"):
    """Build an aws_groups dict with a single group and the given members."""
    return {name: {"GroupId": group_id, "Members": set(members)}}


def _holding(members=(), group_id="holding_id"):
    """Build a holding-group info dict."""
    return {"GroupId": group_id, "Members": set(members)}


def _ic_user(username, email_type="EntraId"):
    """Build a describe_user response for an Identity Center user."""
    return {
        "UserName": username,
        "Emails": [{"Value": username, "Type": email_type, "Primary": True}],
    }


class TestSyncGroupMembers(unittest.TestCase):
    """Tests for syncing a single group's members into Identity Center."""

    def setUp(self):
        app.identity_center_users.clear()
        app.user_cache.clear()
        self.client = MagicMock()
        self.group_info = {"GroupId": "group_id", "Members": set()}
        self.holding = {"GroupId": "holding_id", "Members": set()}

    def _sync(self, members, dry_run=False, group_info=None, holding=None):
        sync_group_members(
            self.client,
            "store",
            group_info or self.group_info,
            members,
            "group_name",
            holding_group_info=holding or self.holding,
            dry_run=dry_run,
        )

    @patch("function.app.get_identity_center_user_id_by_username")
    def test_existing_user_added_to_group_and_holding(self, mock_get_id):
        mock_get_id.return_value = "existing_user_id"

        self._sync([_member()])

        self.client.create_user.assert_not_called()
        # Added to both the group and the holding group.
        self.assertEqual(self.client.create_group_membership.call_count, 2)
        self.assertIn("user1@justice.gov.uk", self.group_info["Members"])
        self.assertIn("user1@justice.gov.uk", self.holding["Members"])

    @patch("function.app.get_identity_center_user_id_by_username")
    def test_new_user_created_and_registered(self, mock_get_id):
        mock_get_id.return_value = None
        self.client.create_user.return_value = {"UserId": "new_user_id"}

        self._sync([_member()])

        self.client.create_user.assert_called_once()
        self.assertEqual(self.client.create_group_membership.call_count, 2)
        # Newly created user is registered in the module index for later groups.
        self.assertEqual(
            app.identity_center_users["user1@justice.gov.uk"]["UserId"], "new_user_id"
        )

    @patch("function.app.get_identity_center_user_id_by_username")
    def test_existing_user_dry_run_would_add_to_group_and_holding(self, mock_get_id):
        # Existing user in dry run: logs intent but makes no membership calls.
        mock_get_id.return_value = "existing_user_id"

        self._sync([_member()], dry_run=True)

        self.client.create_user.assert_not_called()
        self.client.create_group_membership.assert_not_called()
        self.assertNotIn("user1@justice.gov.uk", self.group_info["Members"])
        self.assertNotIn("user1@justice.gov.uk", self.holding["Members"])

    @patch("function.app.get_identity_center_user_id_by_username")
    def test_new_user_dry_run_makes_no_changes(self, mock_get_id):
        mock_get_id.return_value = None

        self._sync([_member()], dry_run=True)

        self.client.create_user.assert_not_called()
        self.client.create_group_membership.assert_not_called()

    @patch("function.app.get_identity_center_user_id_by_username")
    def test_existing_member_not_re_added(self, mock_get_id):
        mock_get_id.return_value = "existing_user_id"
        self.group_info["Members"] = {"user1@justice.gov.uk"}
        self.holding["Members"] = {"user1@justice.gov.uk"}

        self._sync([_member()])

        self.client.create_user.assert_not_called()
        self.client.create_group_membership.assert_not_called()

    @patch("function.app.get_identity_center_user_id_by_username")
    def test_member_with_no_resolvable_address_skipped(self, mock_get_id):
        # No userPrincipalName or mail -> resolve_upn returns "".
        self._sync([{"givenName": "No", "surname": "Address"}])

        mock_get_id.assert_not_called()
        self.client.create_user.assert_not_called()

    @patch("function.app.get_identity_center_user_id_by_username")
    def test_create_user_client_error_is_logged_not_raised(self, mock_get_id):
        mock_get_id.return_value = None
        self.client.create_user.side_effect = ClientError(
            {"Error": {"Code": "InternalFailure", "Message": "boom"}}, "CreateUser"
        )

        # Error is caught; no user id, so no group membership is attempted.
        self._sync([_member()])

        self.client.create_group_membership.assert_not_called()

    @patch("function.app.get_identity_center_user_id_by_username")
    def test_create_user_param_validation_error_is_logged(self, mock_get_id):
        mock_get_id.return_value = None
        self.client.create_user.side_effect = ParamValidationError(report="bad")

        self._sync([_member()])

        self.client.create_group_membership.assert_not_called()

    @patch("function.app.get_identity_center_user_id_by_username")
    def test_no_user_id_dry_run_skips_quietly(self, mock_get_id):
        # In dry run a missing user is expected (would have been created), so
        # membership is simply skipped without the error branch.
        mock_get_id.return_value = None

        self._sync([_member()], dry_run=True)

        self.client.create_group_membership.assert_not_called()

    @patch("function.app.get_identity_center_user_id_by_username")
    def test_givenname_surname_fallback_to_display_name(self, mock_get_id):
        mock_get_id.return_value = None
        self.client.create_user.return_value = {"UserId": "new_user_id"}

        # Guest with null givenName/surname and no displayName.
        self._sync([{"userPrincipalName": "guest@cica.gov.uk"}])

        _, kwargs = self.client.create_user.call_args
        self.assertEqual(kwargs["Name"]["GivenName"], "guest@cica.gov.uk")
        self.assertEqual(kwargs["Name"]["FamilyName"], "guest@cica.gov.uk")

    @patch("function.app.get_identity_center_user_id_by_username")
    def test_group_membership_conflict_treated_as_success(self, mock_get_id):
        mock_get_id.return_value = "existing_user_id"
        self.client.create_group_membership.side_effect = _conflict_error(
            "CreateGroupMembership"
        )

        self._sync([_member()])

        # Despite the conflict on both group and holding, membership is recorded.
        self.assertIn("user1@justice.gov.uk", self.group_info["Members"])
        self.assertIn("user1@justice.gov.uk", self.holding["Members"])

    @patch("function.app.get_identity_center_user_id_by_username")
    def test_group_membership_other_client_error_logged(self, mock_get_id):
        mock_get_id.return_value = "existing_user_id"
        self.client.create_group_membership.side_effect = ClientError(
            {"Error": {"Code": "InternalFailure", "Message": "boom"}},
            "CreateGroupMembership",
        )

        self._sync([_member()])

        # Membership not recorded because both attempts errored.
        self.assertNotIn("user1@justice.gov.uk", self.group_info["Members"])

    @patch("function.app.get_identity_center_user_id_by_username")
    def test_group_membership_param_validation_error_logged(self, mock_get_id):
        mock_get_id.return_value = "existing_user_id"
        # Only the group add raises; the holding block does not catch
        # ParamValidationError, so let the holding add succeed.
        self.client.create_group_membership.side_effect = [
            ParamValidationError(report="bad"),
            None,
        ]

        self._sync([_member()])

        self.assertNotIn("user1@justice.gov.uk", self.group_info["Members"])

    @patch("function.app.get_identity_center_user_id_by_username")
    def test_holding_group_conflict_treated_as_success(self, mock_get_id):
        mock_get_id.return_value = "existing_user_id"
        # Group add succeeds; holding add raises a conflict.
        self.client.create_group_membership.side_effect = [
            None,
            _conflict_error("CreateGroupMembership"),
        ]

        self._sync([_member()])

        self.assertIn("user1@justice.gov.uk", self.holding["Members"])

    @patch("function.app.get_identity_center_user_id_by_username")
    def test_holding_group_other_error_logged(self, mock_get_id):
        mock_get_id.return_value = "existing_user_id"
        self.client.create_group_membership.side_effect = [
            None,
            ClientError(
                {"Error": {"Code": "InternalFailure", "Message": "boom"}},
                "CreateGroupMembership",
            ),
        ]

        self._sync([_member()])

        self.assertNotIn("user1@justice.gov.uk", self.holding["Members"])


class TestSyncAzureGroupsWithAws(unittest.TestCase):
    """Tests for the top-level group sync orchestrator."""

    def setUp(self):
        app.group_members_cache.clear()
        app.identity_center_users.clear()

    @patch("function.app.get_entraid_group_members")
    @patch("function.app.get_azure_access_token")
    @patch("function.app.sync_group_members")
    def test_creates_missing_group(self, mock_sync, mock_token, mock_members):
        mock_token.return_value = "token"
        mock_members.return_value = [_member()]
        client = MagicMock()
        client.create_group.return_value = {"GroupId": "new_group_id"}

        aws_groups = {HOLDING_GROUP_NAME: {"GroupId": "holding_id", "Members": set()}}
        azure_groups = [{"displayName": "azure-aws-sso-group1", "id": "g1"}]

        result = sync_azure_groups_with_aws(
            client, "store", aws_groups, azure_groups, dry_run=False
        )

        client.create_group.assert_called_once()
        self.assertEqual(aws_groups["azure-aws-sso-group1"]["GroupId"], "new_group_id")
        self.assertIn("azure-aws-sso-group1", result)
        mock_sync.assert_called_once()

    @patch("function.app.get_entraid_group_members")
    @patch("function.app.get_azure_access_token")
    @patch("function.app.sync_group_members")
    def test_dry_run_uses_dummy_group(self, _mock_sync, mock_token, mock_members):
        mock_token.return_value = "token"
        mock_members.return_value = []
        client = MagicMock()

        aws_groups = {HOLDING_GROUP_NAME: {"GroupId": "holding_id", "Members": set()}}
        azure_groups = [{"displayName": "azure-aws-sso-group1", "id": "g1"}]

        sync_azure_groups_with_aws(
            client, "store", aws_groups, azure_groups, dry_run=True
        )

        client.create_group.assert_not_called()
        self.assertTrue(
            aws_groups["azure-aws-sso-group1"]["GroupId"].startswith("dry_run_dummy")
        )

    @patch("function.app.get_entraid_group_members")
    @patch("function.app.get_azure_access_token")
    @patch("function.app.sync_group_members")
    def test_existing_group_not_recreated(self, _mock_sync, mock_token, mock_members):
        mock_token.return_value = "token"
        mock_members.return_value = []
        client = MagicMock()

        aws_groups = {
            HOLDING_GROUP_NAME: {"GroupId": "holding_id", "Members": set()},
            "azure-aws-sso-group1": {"GroupId": "existing_id", "Members": set()},
        }
        azure_groups = [{"displayName": "azure-aws-sso-group1", "id": "g1"}]

        sync_azure_groups_with_aws(
            client, "store", aws_groups, azure_groups, dry_run=False
        )

        client.create_group.assert_not_called()


class TestRemoveObsoleteGroups(unittest.TestCase):
    """Tests for removing AWS groups no longer present in Azure."""

    def test_deletes_group_absent_from_azure(self):
        client = MagicMock()
        aws_groups = {"azure-aws-sso-old": {"GroupId": "old_id", "Members": set()}}

        remove_obsolete_groups(client, "store", aws_groups, [], dry_run=False)

        client.delete_group.assert_called_once_with(
            IdentityStoreId="store", GroupId="old_id"
        )
        self.assertNotIn("azure-aws-sso-old", aws_groups)

    def test_dry_run_deletes_locally_only(self):
        client = MagicMock()
        aws_groups = {"azure-aws-sso-old": {"GroupId": "old_id", "Members": set()}}

        remove_obsolete_groups(client, "store", aws_groups, [], dry_run=True)

        client.delete_group.assert_not_called()
        self.assertNotIn("azure-aws-sso-old", aws_groups)

    def test_keeps_group_still_in_azure(self):
        client = MagicMock()
        aws_groups = {"azure-aws-sso-keep": {"GroupId": "id", "Members": set()}}
        azure_groups = [{"displayName": "azure-aws-sso-keep"}]

        remove_obsolete_groups(client, "store", aws_groups, azure_groups, dry_run=False)

        client.delete_group.assert_not_called()
        self.assertIn("azure-aws-sso-keep", aws_groups)

    def test_skips_ignored_group(self):
        client = MagicMock()
        ignored = "azure-aws-sso-analytical-platform-qs-readers"
        aws_groups = {ignored: {"GroupId": "id", "Members": set()}}

        remove_obsolete_groups(client, "store", aws_groups, [], dry_run=False)

        client.delete_group.assert_not_called()
        self.assertIn(ignored, aws_groups)

    def test_never_deletes_holding_group(self):
        client = MagicMock()
        aws_groups = {HOLDING_GROUP_NAME: {"GroupId": "holding_id", "Members": set()}}

        remove_obsolete_groups(client, "store", aws_groups, [], dry_run=False)

        client.delete_group.assert_not_called()
        self.assertIn(HOLDING_GROUP_NAME, aws_groups)

    def test_delete_client_error_is_logged(self):
        client = MagicMock()
        client.delete_group.side_effect = ClientError(
            {"Error": {"Code": "InternalFailure", "Message": "boom"}}, "DeleteGroup"
        )
        aws_groups = {"azure-aws-sso-old": {"GroupId": "old_id", "Members": set()}}

        remove_obsolete_groups(client, "store", aws_groups, [], dry_run=False)

        # Deletion failed, so the group remains in the dict.
        self.assertIn("azure-aws-sso-old", aws_groups)


class TestRemoveMembersNotInAzureGroups(unittest.TestCase):
    """Tests for pruning members that dropped out of the Azure group."""

    def setUp(self):
        app.identity_center_users.clear()
        app.user_cache.clear()

    @staticmethod
    def _prune(client, aws_groups, holding, azure_group_members, dry_run=False):
        remove_members_not_in_azure_groups(
            client, "store", aws_groups, azure_group_members, holding, dry_run=dry_run
        )

    def _prune_stale(self, client=None):
        """Prune the standard single stale member that Azure no longer lists."""
        client = client or MagicMock()
        self._prune(
            client,
            _aws_group(["stale@justice.gov.uk"]),
            _holding(),
            {"azure-aws-sso-group1": []},
        )
        return client

    @patch("function.app.get_group_membership_id")
    @patch("function.app.get_identity_center_user_id_by_username")
    def test_removes_member_and_deletes_user(self, mock_get_id, mock_membership):
        mock_get_id.return_value = "user_id"
        # Group membership id, then holding membership id.
        mock_membership.side_effect = ["m_group", "m_holding"]
        client = MagicMock()
        aws_groups = _aws_group(["stale@justice.gov.uk"])
        # Azure no longer lists the stale user.
        self._prune(
            client,
            aws_groups,
            _holding(["stale@justice.gov.uk"]),
            {"azure-aws-sso-group1": [_member("live@justice.gov.uk")]},
        )

        self.assertEqual(client.delete_group_membership.call_count, 2)
        client.delete_user.assert_called_once_with(
            IdentityStoreId="store", UserId="user_id"
        )
        self.assertNotIn(
            "stale@justice.gov.uk", aws_groups["azure-aws-sso-group1"]["Members"]
        )

    @patch("function.app.get_group_membership_id")
    @patch("function.app.get_identity_center_user_id_by_username")
    def test_dry_run_makes_no_changes(self, mock_get_id, mock_membership):
        mock_get_id.return_value = "user_id"
        mock_membership.return_value = "m_group"
        client = MagicMock()

        self._prune(
            client,
            _aws_group(["stale@justice.gov.uk"]),
            _holding(),
            {"azure-aws-sso-group1": []},
            dry_run=True,
        )

        client.delete_group_membership.assert_not_called()
        client.delete_user.assert_not_called()

    def test_skips_holding_group(self):
        client = MagicMock()
        aws_groups = {HOLDING_GROUP_NAME: {"GroupId": "holding_id", "Members": {"x"}}}
        self._prune(client, aws_groups, _holding(["x"]), {HOLDING_GROUP_NAME: []})

        client.delete_group_membership.assert_not_called()

    def test_group_missing_from_aws_is_warned(self):
        client = MagicMock()
        self._prune(client, {}, _holding(), {"azure-aws-sso-group1": [_member()]})

        client.delete_group_membership.assert_not_called()

    @patch("function.app.get_identity_center_user_id_by_username")
    def test_no_members_to_remove(self, mock_get_id):
        client = MagicMock()
        self._prune(
            client,
            _aws_group(["live@justice.gov.uk"]),
            _holding(),
            {"azure-aws-sso-group1": [_member("live@justice.gov.uk")]},
        )

        mock_get_id.assert_not_called()
        client.delete_group_membership.assert_not_called()

    @patch("function.app.get_identity_center_user_id_by_username")
    def test_missing_user_id_is_warned(self, mock_get_id):
        mock_get_id.return_value = None
        client = self._prune_stale()

        client.delete_group_membership.assert_not_called()

    @patch("function.app.get_group_membership_id")
    @patch("function.app.get_identity_center_user_id_by_username")
    def test_missing_membership_id_is_warned(self, mock_get_id, mock_membership):
        mock_get_id.return_value = "user_id"
        mock_membership.return_value = None
        client = self._prune_stale()

        client.delete_group_membership.assert_not_called()

    @patch("function.app.get_group_membership_id")
    @patch("function.app.get_identity_center_user_id_by_username")
    def test_no_holding_membership_still_deletes_user(
        self, mock_get_id, mock_membership
    ):
        mock_get_id.return_value = "user_id"
        # Group membership present; user not in holding group.
        mock_membership.side_effect = ["m_group", None]
        client = self._prune_stale()

        client.delete_group_membership.assert_called_once()
        client.delete_user.assert_called_once()

    @patch("function.app.get_group_membership_id")
    @patch("function.app.get_identity_center_user_id_by_username")
    def test_delete_client_error_is_logged(self, mock_get_id, mock_membership):
        mock_get_id.return_value = "user_id"
        mock_membership.side_effect = ["m_group", "m_holding"]
        client = MagicMock()
        client.delete_group_membership.side_effect = ClientError(
            {"Error": {"Code": "InternalFailure", "Message": "boom"}},
            "DeleteGroupMembership",
        )
        self._prune_stale(client)

        client.delete_user.assert_not_called()


class TestDeleteOrphanedAwsUsers(unittest.TestCase):
    """Tests for deleting users who belong to no relevant group."""

    def setUp(self):
        app.identity_center_users.clear()
        app.user_cache.clear()

    @staticmethod
    def _delete_orphans(client, aws_groups, holding, dry_run=False):
        delete_orphaned_aws_users(
            client, "store", aws_groups, {"user_id"}, holding, dry_run=dry_run
        )

    @patch("function.app.get_group_membership_id")
    def test_deletes_orphan_with_matching_email(self, mock_membership):
        mock_membership.return_value = "m_holding"
        client = MagicMock()
        client.describe_user.return_value = _ic_user("orphan@justice.gov.uk")

        self._delete_orphans(
            client,
            {"azure-aws-sso-group1": {"Members": set()}},
            _holding(["orphan@justice.gov.uk"]),
        )

        client.delete_group_membership.assert_called_once()
        client.delete_user.assert_called_once_with(
            IdentityStoreId="store", UserId="user_id"
        )

    def test_keeps_user_still_in_a_group(self):
        client = MagicMock()
        client.describe_user.return_value = _ic_user("member@justice.gov.uk")

        self._delete_orphans(
            client,
            {"azure-aws-sso-group1": {"Members": {"member@justice.gov.uk"}}},
            _holding(),
        )

        client.delete_user.assert_not_called()

    def test_keeps_user_without_matching_email(self):
        client = MagicMock()
        client.describe_user.return_value = _ic_user(
            "external@justice.gov.uk", email_type="Work"
        )

        self._delete_orphans(
            client, {"azure-aws-sso-group1": {"Members": set()}}, _holding()
        )

        client.delete_user.assert_not_called()

    @patch("function.app.get_group_membership_id")
    def test_dry_run_makes_no_changes(self, mock_membership):
        client = MagicMock()
        client.describe_user.return_value = _ic_user("orphan@justice.gov.uk")

        self._delete_orphans(
            client,
            {"azure-aws-sso-group1": {"Members": set()}},
            _holding(),
            dry_run=True,
        )

        mock_membership.assert_not_called()
        client.delete_user.assert_not_called()

    @patch("function.app.get_group_membership_id")
    def test_orphan_not_in_holding_group_still_deleted(self, mock_membership):
        mock_membership.return_value = None
        client = MagicMock()
        client.describe_user.return_value = _ic_user("orphan@justice.gov.uk")

        self._delete_orphans(
            client, {"azure-aws-sso-group1": {"Members": set()}}, _holding()
        )

        client.delete_group_membership.assert_not_called()
        client.delete_user.assert_called_once()

    def test_describe_user_client_error_is_logged(self):
        client = MagicMock()
        client.describe_user.side_effect = ClientError(
            {"Error": {"Code": "ResourceNotFoundException", "Message": "no"}},
            "DescribeUser",
        )

        self._delete_orphans(
            client, {"azure-aws-sso-group1": {"Members": set()}}, _holding()
        )

        client.delete_user.assert_not_called()


if __name__ == "__main__":
    unittest.main()
