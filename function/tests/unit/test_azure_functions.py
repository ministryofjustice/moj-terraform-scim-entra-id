# The app module raises at import time unless the Azure credentials are set,
# so provide dummy values before importing it. pylint: disable=wrong-import-position
import os
import unittest
from unittest.mock import MagicMock, patch

os.environ.setdefault("AZURE_TENANT_ID", "test-tenant")
os.environ.setdefault("AZURE_CLIENT_ID", "test-client")
os.environ.setdefault("AZURE_CLIENT_SECRET", "test-secret")

from function import app  # noqa: E402
from function.app import (  # noqa: E402
    get_azure_access_token,
    get_entraid_aws_groups,
    get_entraid_group_members,
    graph_get_all,
    resolve_upn,
)


class TestResolveUpn(unittest.TestCase):
    """Tests for resolving the real email address of an Entra member."""

    def test_plain_allowed_upn(self):
        member = {"userPrincipalName": "user1@justice.gov.uk"}
        self.assertEqual(resolve_upn(member), "user1@justice.gov.uk")

    def test_b2b_guest_upn_is_decoded(self):
        # Mangled B2B guest UPN should decode to the real cica.gov.uk address.
        member = {
            "userPrincipalName": "Jane.Doe_CICA.GOV.UK#EXT#@JusticeUK.onmicrosoft.com"
        }
        self.assertEqual(resolve_upn(member), "Jane.Doe@CICA.GOV.UK")

    def test_b2b_guest_local_part_with_underscore(self):
        # rsplit ensures underscores in the local part survive decoding.
        member = {
            "userPrincipalName": "jane_doe_YJB.GOV.UK#EXT#@JusticeUK.onmicrosoft.com"
        }
        self.assertEqual(resolve_upn(member), "jane_doe@YJB.GOV.UK")

    def test_falls_back_to_mail_when_upn_not_allowed(self):
        member = {
            "userPrincipalName": "user@contoso.onmicrosoft.com",
            "mail": "user@justice.gov.uk",
        }
        self.assertEqual(resolve_upn(member), "user@justice.gov.uk")

    def test_no_allowed_candidate_returns_mail(self):
        member = {
            "userPrincipalName": "user@contoso.com",
            "mail": "user@external.com",
        }
        # No allowed domain, so falls back to mail.
        self.assertEqual(resolve_upn(member), "user@external.com")

    def test_no_allowed_candidate_no_mail_returns_upn(self):
        member = {"userPrincipalName": "user@contoso.com"}
        self.assertEqual(resolve_upn(member), "user@contoso.com")

    def test_empty_member_returns_empty_string(self):
        self.assertEqual(resolve_upn({}), "")


class TestGraphGetAll(unittest.TestCase):
    """Tests for the paginated Microsoft Graph collection helper."""

    @patch("function.app.requests.get")
    def test_follows_next_link_until_exhausted(self, mock_get):
        first = MagicMock()
        first.json.return_value = {
            "value": [{"id": "1"}],
            "@odata.nextLink": "https://graph.microsoft.com/next",
        }
        second = MagicMock()
        second.json.return_value = {"value": [{"id": "2"}]}
        mock_get.side_effect = [first, second]

        result = graph_get_all("https://graph.microsoft.com/start", {"h": "v"})

        self.assertEqual([item["id"] for item in result], ["1", "2"])
        self.assertEqual(mock_get.call_count, 2)
        # The second request must not carry the original params - the nextLink
        # already encodes the query string.
        self.assertIsNone(mock_get.call_args_list[1].kwargs["params"])

    @patch("function.app.requests.get")
    def test_raises_for_status(self, mock_get):
        response = MagicMock()
        response.raise_for_status.side_effect = Exception("boom")
        mock_get.return_value = response

        with self.assertRaises(Exception):
            graph_get_all("https://graph.microsoft.com/start", {})


class TestAzureFunctions(unittest.TestCase):
    """
    Unit tests for Azure-related functions in the AWS Identity Center integration.
    """

    def setUp(self):
        # Caches are module globals that survive between tests.
        app.group_members_cache.clear()

    @patch("function.app.requests.post")
    def test_get_azure_access_token(self, mock_post):
        mock_response = MagicMock()
        mock_response.json.return_value = {"access_token": "mocked_access_token"}
        mock_post.return_value = mock_response

        token = get_azure_access_token()
        self.assertEqual(token, "mocked_access_token")

    @patch("function.app.requests.post")
    def test_get_azure_access_token_failure(self, mock_post):
        mock_post.side_effect = Exception("Failed to obtain token")

        with self.assertRaises(Exception) as context:
            get_azure_access_token()
        self.assertIn("Failed to obtain token", str(context.exception))

    @patch("function.app.requests.get")
    def test_get_entraid_aws_groups_filters_ignored(self, mock_get):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "value": [
                {"displayName": "azure-aws-sso-group1"},
                {"displayName": "azure-aws-sso-analytical-platform-qs-readers"},
            ]
        }
        mock_get.return_value = mock_response

        groups = get_entraid_aws_groups("mocked_access_token")
        # The ignored group is dropped.
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["displayName"], "azure-aws-sso-group1")

    @patch("function.app.requests.get")
    def test_get_entraid_group_members_filters_by_domain(self, mock_get):
        members_response = MagicMock()
        owners_response = MagicMock()
        members_response.json.return_value = {
            "value": [
                {"userPrincipalName": "user1@justice.gov.uk"},
                {"userPrincipalName": "outsider@contoso.com"},
            ]
        }
        owners_response.json.return_value = {
            "value": [{"userPrincipalName": "admin1@yjb.gov.uk"}]
        }
        mock_get.side_effect = [members_response, owners_response]

        members = get_entraid_group_members("mocked_access_token", "group1")

        # Only allowed-domain members and admins survive filtering.
        self.assertEqual(
            {resolve_upn(m) for m in members},
            {"user1@justice.gov.uk", "admin1@yjb.gov.uk"},
        )

    @patch("function.app.requests.get")
    def test_get_entraid_group_members_uses_cache(self, mock_get):
        members_response = MagicMock()
        owners_response = MagicMock()
        members_response.json.return_value = {
            "value": [{"userPrincipalName": "user1@justice.gov.uk"}]
        }
        owners_response.json.return_value = {"value": []}
        mock_get.side_effect = [members_response, owners_response]

        first = get_entraid_group_members("mocked_access_token", "group1")
        call_count_after_first = mock_get.call_count
        second = get_entraid_group_members("mocked_access_token", "group1")

        self.assertEqual(first, second)
        # The second call must be served from cache, issuing no HTTP requests.
        self.assertEqual(mock_get.call_count, call_count_after_first)


if __name__ == "__main__":
    unittest.main()
