# Credentials must be set before importing the app module, which validates them
# at import time. pylint: disable=wrong-import-position
import importlib
import os
import unittest
from unittest.mock import DEFAULT, MagicMock, patch

from botocore.exceptions import ClientError

os.environ.setdefault("AZURE_TENANT_ID", "test-tenant")
os.environ.setdefault("AZURE_CLIENT_ID", "test-client")
os.environ.setdefault("AZURE_CLIENT_SECRET", "test-secret")

from function import app  # noqa: E402
from function.app import HOLDING_GROUP_NAME, lambda_handler  # noqa: E402


class TestLambdaHandler(unittest.TestCase):
    """
    Tests for the top-level Lambda entry point, with all collaborating
    functions patched so only the handler's own orchestration is exercised.
    """

    def setUp(self):
        # The handler clears these itself, but seed them so we can prove it does.
        app.user_cache["stale"] = "value"
        app.group_members_cache["stale"] = []
        app.identity_center_users["stale"] = {}

    def _patches(self):
        # patch.multiple only returns mocks in the `with` dict for names set to
        # DEFAULT, so configure return values on the yielded mocks instead.
        return patch.multiple(
            "function.app",
            boto3=DEFAULT,
            get_identity_store_id=DEFAULT,
            get_azure_access_token=DEFAULT,
            get_entraid_aws_groups=DEFAULT,
            get_identity_center_groups_and_relevant_users=DEFAULT,
            sync_azure_groups_with_aws=DEFAULT,
            remove_obsolete_groups=DEFAULT,
            remove_members_not_in_azure_groups=DEFAULT,
            delete_orphaned_aws_users=DEFAULT,
        )

    @staticmethod
    def _configure(mocks):
        mocks["get_identity_store_id"].return_value = "store"
        mocks["get_azure_access_token"].return_value = "token"
        mocks["get_entraid_aws_groups"].return_value = [
            {"displayName": "azure-aws-sso-group1", "id": "g1"}
        ]
        mocks["get_identity_center_groups_and_relevant_users"].return_value = (
            {},
            set(),
        )
        mocks["sync_azure_groups_with_aws"].return_value = {}

    def test_success_creates_holding_group_and_clears_caches(self):
        with self._patches() as mocks:
            self._configure(mocks)
            client = MagicMock()
            client.create_group.return_value = {"GroupId": "holding_id"}
            mocks["boto3"].client.return_value = client

            response = lambda_handler({"dry_run": False}, None)

        self.assertEqual(response["statusCode"], 200)
        self.assertIn("Completed", response["body"])
        # Caches were cleared at the start of the run.
        self.assertNotIn("stale", app.user_cache)
        self.assertNotIn("stale", app.group_members_cache)
        self.assertNotIn("stale", app.identity_center_users)
        mocks["sync_azure_groups_with_aws"].assert_called_once()

    def test_dry_run_creates_dummy_holding_group(self):
        with self._patches() as mocks:
            self._configure(mocks)
            client = MagicMock()
            mocks["boto3"].client.return_value = client

            # Default event -> dry_run defaults to "True".
            response = lambda_handler({}, None)

        self.assertEqual(response["statusCode"], 200)
        client.create_group.assert_not_called()

    def test_existing_holding_group_not_recreated(self):
        with self._patches() as mocks:
            self._configure(mocks)
            mocks["get_identity_center_groups_and_relevant_users"].return_value = (
                {HOLDING_GROUP_NAME: {"GroupId": "existing", "Members": set()}},
                set(),
            )
            client = MagicMock()
            mocks["boto3"].client.return_value = client

            response = lambda_handler({"dry_run": False}, None)

        self.assertEqual(response["statusCode"], 200)
        client.create_group.assert_not_called()

    def test_holding_group_creation_failure_returns_500(self):
        with self._patches() as mocks:
            self._configure(mocks)
            client = MagicMock()
            client.create_group.side_effect = ClientError(
                {"Error": {"Code": "InternalFailure", "Message": "boom"}},
                "CreateGroup",
            )
            mocks["boto3"].client.return_value = client

            response = lambda_handler({"dry_run": False}, None)

        self.assertEqual(response["statusCode"], 500)
        self.assertIn("error", response["body"])

    def test_unexpected_exception_returns_500(self):
        with self._patches() as mocks:
            self._configure(mocks)
            mocks["get_azure_access_token"].side_effect = RuntimeError("kaboom")
            mocks["boto3"].client.return_value = MagicMock()

            response = lambda_handler({"dry_run": False}, None)

        self.assertEqual(response["statusCode"], 500)
        self.assertIn("kaboom", response["body"])


class TestModuleImportGuard(unittest.TestCase):
    """The module must refuse to import when required env vars are missing."""

    def tearDown(self):
        # Restore a well-formed module for any tests that run afterwards.
        with patch.dict(
            os.environ,
            {
                "AZURE_TENANT_ID": "test-tenant",
                "AZURE_CLIENT_ID": "test-client",
                "AZURE_CLIENT_SECRET": "test-secret",
            },
        ):
            importlib.reload(app)

    def test_missing_env_var_raises_environment_error(self):
        # Reload the module in-process with a required var unset so the guard
        # executes (and is measured by coverage).
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(EnvironmentError) as ctx:
                importlib.reload(app)
        self.assertIn("Missing required environment variable", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
