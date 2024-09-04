import unittest
from unittest.mock import MagicMock, patch

from function.app import (
    get_azure_access_token,
    get_entraid_aws_groups,
    get_entraid_group_members,
)


class TestAzureFunctions(unittest.TestCase):
    @patch("function.app.requests.post")
    def test_get_azure_access_token(self, mock_post):
        # Mock the Azure token response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"access_token": "mocked_access_token"}
        mock_post.return_value = mock_response

        token = get_azure_access_token()
        self.assertEqual(token, "mocked_access_token")

    @patch("function.app.requests.post")
    def test_get_azure_access_token_failure(self, mock_post):
        # Mock the Azure token response failure
        mock_post.side_effect = Exception("Failed to obtain token")

        with self.assertRaises(Exception) as context:
            get_azure_access_token()
        self.assertIn("Failed to obtain token", str(context.exception))

    @patch("function.app.requests.get")
    def test_get_entraid_aws_groups(self, mock_get):
        # Mock the Azure groups response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "value": [{"displayName": "entraid-aws-identitycenter-group1"}]
        }
        mock_get.return_value = mock_response

        groups = get_entraid_aws_groups("mocked_access_token")
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["displayName"], "entraid-aws-identitycenter-group1")

    @patch("function.app.requests.get")
    def test_get_entraid_group_members(self, mock_get):
        # Mock the Azure group members response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.side_effect = [
            {"value": [{"userPrincipalName": "user1@example.com"}]},
            {"value": [{"userPrincipalName": "admin1@example.com"}]},
        ]
        mock_get.return_value = mock_response

        members = get_entraid_group_members("mocked_access_token", "mocked_group_id")
        self.assertEqual(len(members), 2)
        self.assertEqual(
            set(member["userPrincipalName"] for member in members),
            {"user1@example.com", "admin1@example.com"},
        )


if __name__ == "__main__":
    unittest.main()
