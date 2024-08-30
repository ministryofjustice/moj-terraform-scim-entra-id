import os
import json
import logging
import requests
import boto3
from botocore.exceptions import ClientError
import sys
import traceback

# Initialize environment variables
TENANT_ID = os.environ.get("AZURE_TENANT_ID")
CLIENT_ID = os.environ.get("AZURE_CLIENT_ID")
CLIENT_SECRET = os.environ.get("AZURE_CLIENT_SECRET")
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

GROUP_PREFIX = "azure-aws-sso-"

# Set up logging
logger = logging.getLogger()
logger.setLevel(LOG_LEVEL)
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(LOG_LEVEL)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)

# Checking for missing envvars
required_env_vars = ["AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"]
for var in required_env_vars:
    if not os.environ.get(var):
        logger.error(f"Environment variable '{var}' is required but not set.")
        raise EnvironmentError(f"Missing required environment variable: {var}")

# Cache for storing user and group data
user_cache = {}
group_members_cache = {}


def get_identity_store_id(sso_client):
    """
    Retrieve the Identity Store ID from AWS SSO.

    Args:
        sso_client: Boto3 client for AWS SSO.

    Returns:
        str: Identity Store ID.
    """
    response = sso_client.list_instances()
    return response["Instances"][0]["IdentityStoreId"]


def get_azure_access_token():
    """
    Obtain an access token from Azure AD for accessing Microsoft Graph API.

    Returns:
        str: Access token.
    """
    url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {
        "grant_type": "client_credentials",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "scope": "https://graph.microsoft.com/.default",
    }

    response = requests.post(url, headers=headers, data=data)
    response.raise_for_status()
    return response.json()["access_token"]


def get_entraid_aws_groups(access_token):
    """
    Retrieve groups from Azure AD that are prefixed with a specific string.

    Args:
        access_token (str): Access token for Microsoft Graph API.

    Returns:
        list: List of groups.
    """
    url = "https://graph.microsoft.com/v1.0/groups"
    headers = {"Authorization": f"Bearer {access_token}"}
    params = {"$filter": f"startswith(displayName, '{GROUP_PREFIX}')"}

    response = requests.get(url, headers=headers, params=params)
    response.raise_for_status()
    return response.json()["value"]


def get_entraid_group_members(access_token, group_id):
    """
    Retrieve members and admins of a specific Azure AD group.

    Args:
        access_token (str): Access token for Microsoft Graph API.
        group_id (str): ID of the Azure AD group.

    Returns:
        list: List of members and admins.
    """
    if group_id in group_members_cache:
        return group_members_cache[group_id]

    headers = {"Authorization": f"Bearer {access_token}"}

    # Fetch members
    url_members = f"https://graph.microsoft.com/v1.0/groups/{group_id}/members"
    response_members = requests.get(url_members, headers=headers)
    response_members.raise_for_status()
    members = response_members.json()["value"]

    # Fetch admins
    url_admins = f"https://graph.microsoft.com/v1.0/groups/{group_id}/owners"
    response_admins = requests.get(url_admins, headers=headers)
    response_admins.raise_for_status()
    admins = response_admins.json()["value"]

    # Combine members and admins
    combined_members = members + admins

    group_members_cache[group_id] = combined_members
    return combined_members


def get_identity_center_groups_and_relevant_users(
    identity_center_client, identity_store_id, group_name_prefix=""
):
    """
    Retrieve AWS Identity Center groups and their memberships.

    Args:
        identity_center_client: Boto3 client for Identity Center.
        identity_store_id (str): Identity Store ID.
        group_name_prefix (str): Prefix to filter groups.

    Returns:
        tuple: A dictionary of groups and a set of relevant users.
    """
    try:
        logger.info("Fetching AWS Identity Center groups and their memberships...")
        groups = {}
        relevant_users = set()

        paginator = identity_center_client.get_paginator("list_groups")
        for page in paginator.paginate(IdentityStoreId=identity_store_id):
            for group in page["Groups"]:
                if group_name_prefix == "" or group["DisplayName"].startswith(
                    group_name_prefix
                ):
                    groups[group["DisplayName"]] = {
                        "GroupId": group["GroupId"],
                        "Members": set(),
                    }

        for group_name, group_info in groups.items():
            logger.info(f"Fetching members for group: {group_name}")
            paginator = identity_center_client.get_paginator("list_group_memberships")
            for page in paginator.paginate(
                IdentityStoreId=identity_store_id, GroupId=group_info["GroupId"]
            ):
                for membership in page["GroupMemberships"]:
                    user_id = membership["MemberId"]["UserId"]
                    username = get_identity_center_username(
                        identity_center_client, identity_store_id, user_id
                    )
                    if username:
                        group_info["Members"].add(username)
                        relevant_users.add(user_id)

        logger.info(
            f"Number of Identity Center groups retrieved with prefix '{group_name_prefix}': {len(groups)}"
        )
        return groups, relevant_users
    except ClientError as e:
        logger.error(f"Error listing Identity Center groups and memberships: {e}")
        raise e


def get_identity_center_username(identity_center_client, identity_store_id, user_id):
    """
    Retrieve the username associated with a user ID in AWS Identity Center.

    Args:
        identity_center_client: Boto3 client for Identity Center.
        identity_store_id (str): Identity Store ID.
        user_id (str): User ID.

    Returns:
        str: Username or None if an error occurs.
    """
    if user_id in user_cache:
        return user_cache[user_id]

    try:
        logger.debug(f"Fetching username for user ID: {user_id}")
        response = identity_center_client.describe_user(
            IdentityStoreId=identity_store_id, UserId=user_id
        )
        username = response.get("UserName")
        if username:
            user_cache[user_id] = username
        return username
    except ClientError as e:
        logger.error(f"Error getting username for user ID {user_id}: {e}")
        return None


def get_identity_center_user_id_by_username(
    identity_center_client, identity_store_id, username
):
    """
    Retrieve the user ID associated with a username in AWS Identity Center.

    Args:
        identity_center_client: Boto3 client for Identity Center.
        identity_store_id (str): Identity Store ID.
        username (str): Username.

    Returns:
        str: User ID or None if the user is not found.
    """
    if username in user_cache:
        return user_cache[username]

    try:
        logger.debug(f"Fetching user ID for username: {username}")
        response = identity_center_client.list_users(
            IdentityStoreId=identity_store_id,
            Filters=[{"AttributePath": "UserName", "AttributeValue": username}],
        )
        if response["Users"]:
            user_id = response["Users"][0]["UserId"]
            user_cache[username] = user_id
            return user_id
    except ClientError as e:
        logger.error(f"Error getting user ID for username {username}: {e}")
    return None


def get_group_membership_id(
    identity_center_client, identity_store_id, group_id, user_id
):
    """
    Retrieve the membership ID for a user in a specific group in AWS Identity Center.

    Args:
        identity_center_client: Boto3 client for Identity Center.
        identity_store_id (str): Identity Store ID.
        group_id (str): Group ID.
        user_id (str): User ID.

    Returns:
        str: Membership ID or None if not found.
    """
    try:
        logger.info(f"Fetching membership ID for user {user_id} in group {group_id}")
        paginator = identity_center_client.get_paginator("list_group_memberships")
        for page in paginator.paginate(
            IdentityStoreId=identity_store_id, GroupId=group_id
        ):
            for membership in page["GroupMemberships"]:
                if membership["MemberId"]["UserId"] == user_id:
                    return membership["MembershipId"]
    except ClientError as e:
        logger.error(
            f"Error getting membership ID for user ID {user_id} in group ID {group_id}: {e}"
        )
    return None


def sync_azure_groups_with_aws(
    identity_center_client, identity_store_id, aws_groups, azure_groups, dry_run
):
    """
    Sync Azure AD groups and their members with AWS Identity Center.

    Args:
        identity_center_client: Boto3 client for Identity Center.
        identity_store_id (str): Identity Store ID.
        aws_groups (dict): Existing AWS Identity Center groups.
        azure_groups (list): List of Azure AD groups to sync.
        dry_run (bool): If True, only log the actions without making changes.

    Returns:
        dict: Dictionary of Azure group members.
    """
    azure_group_members = {}

    for group in azure_groups:
        group_name = group["displayName"]
        group_id = group["id"]
        members = get_entraid_group_members(get_azure_access_token(), group_id)
        azure_group_members[group_name] = members

        if group_name not in aws_groups:
            if dry_run:
                logger.info(
                    f"[Dry Run] Would create group '{group_name}' in AWS Identity Center."
                )
                aws_groups[group_name] = {
                    "GroupId": f"dry_run_dummy_'{group_name}'",
                    "Members": set(),
                }
            else:
                response = identity_center_client.create_group(
                    IdentityStoreId=identity_store_id, DisplayName=group_name
                )
                aws_groups[group_name] = {
                    "GroupId": response["GroupId"],
                    "Members": set(),
                }
                logger.info(f"Created group '{group_name}' in AWS Identity Center.")

        # Sync members
        sync_group_members(
            identity_center_client,
            identity_store_id,
            aws_groups[group_name],
            members,
            group_name,
            dry_run,
        )

    return azure_group_members


def sync_group_members(
    identity_center_client, identity_store_id, group_info, members, group_name, dry_run
):
    """
    Sync members of a specific Azure AD group with AWS Identity Center.

    Args:
        identity_center_client: Boto3 client for Identity Center.
        identity_store_id (str): Identity Store ID.
        group_info (dict): AWS Identity Center group information.
        members (list): List of Azure AD group members.
        group_name (str): Name of the group.
        dry_run (bool): If True, only log the actions without making changes.
    """
    for member in members:
        member_name = member["userPrincipalName"]
        member_given_name = member["givenName"]
        member_surname = member["surname"]

        logger.debug(
            f"Processing member: {member_name}, GivenName: {member_given_name}, Surname: {member_surname}"
        )

        # Check if the user exists
        user_id = get_identity_center_user_id_by_username(
            identity_center_client, identity_store_id, member_name
        )

        if user_id:
            logger.debug(
                f"User '{member_name}' already exists with UserId '{user_id}' in AWS Identity Center."
            )
        else:
            if dry_run:
                logger.info(
                    f"[Dry Run] Would create a new user '{member_name}' in AWS Identity Center."
                )
            else:
                try:
                    logger.info(
                        f"Creating a new user '{member_name}' in AWS Identity Center."
                    )
                    user_response = identity_center_client.create_user(
                        IdentityStoreId=identity_store_id,
                        UserName=member_name,
                        DisplayName=member_name,
                        Name={
                            "FamilyName": member_surname,
                            "GivenName": member_given_name,
                        },
                        Emails=[
                            {"Value": member_name, "Type": "EntraId", "Primary": True}
                        ],
                    )
                    user_id = user_response["UserId"]
                    logger.info(
                        f"Successfully created new user '{member_name}' with UserId '{user_id}' in AWS Identity Center."
                    )
                except ClientError as e:
                    logger.error(
                        f"Failed to create user '{member_name}' in AWS Identity Center: {e}"
                    )
                    raise e

        # Add the user to the group if they are not already a member
        if member_name not in group_info["Members"]:
            if dry_run:
                logger.info(
                    f"[Dry Run] Would add user '{member_name}' to group '{group_name}' in AWS Identity Center."
                )
            else:
                try:
                    logger.info(
                        f"Adding user '{member_name}' to group '{group_name}' in AWS Identity Center."
                    )
                    identity_center_client.create_group_membership(
                        IdentityStoreId=identity_store_id,
                        GroupId=group_info["GroupId"],
                        MemberId={"UserId": user_id},
                    )
                    group_info["Members"].add(member_name)
                    logger.info(
                        f"Successfully added user '{member_name}' to group '{group_name}' in AWS Identity Center."
                    )
                except ClientError as e:
                    if e.response["Error"]["Code"] == "EntityAlreadyExistsException":
                        logger.info(
                            f"User '{member_name}' is already a member of group '{group_name}'."
                        )
                    else:
                        logger.error(
                            f"Failed to add user '{member_name}' to group '{group_name}': {e}"
                        )
                        raise e


def remove_obsolete_groups(
    identity_center_client, identity_store_id, aws_groups, azure_groups, dry_run
):
    """
    Remove AWS Identity Center groups that no longer exist in Azure AD.

    Args:
        identity_center_client: Boto3 client for Identity Center.
        identity_store_id (str): Identity Store ID.
        aws_groups (dict): Existing AWS Identity Center groups.
        azure_groups (list): List of Azure AD groups.
        dry_run (bool): If True, only log the actions without making changes.
    """
    azure_group_names = set(group["displayName"] for group in azure_groups)
    for group_name in list(aws_groups.keys()):
        if group_name not in azure_group_names:
            if dry_run:
                logger.info(
                    f"[Dry Run] Would delete group '{group_name}' from AWS Identity Center."
                )
                group_id = aws_groups[group_name]["GroupId"]
                del aws_groups[group_name]
            else:
                group_id = aws_groups[group_name]["GroupId"]
                try:
                    logger.info(
                        f"Deleting group '{group_name}' from AWS Identity Center."
                    )
                    identity_center_client.delete_group(
                        IdentityStoreId=identity_store_id, GroupId=group_id
                    )
                    del aws_groups[group_name]
                except ClientError as e:
                    logger.error(f"Error deleting group {group_name}: {e}")


def remove_members_not_in_azure_groups(
    identity_center_client, identity_store_id, aws_groups, azure_group_members, dry_run
):
    """
    Remove users from AWS Identity Center groups if they no longer exist in Azure AD groups.

    Args:
        identity_center_client: Boto3 client for Identity Center.
        identity_store_id (str): Identity Store ID.
        aws_groups (dict): Existing AWS Identity Center groups.
        azure_group_members (dict): Dictionary of Azure AD group members.
        dry_run (bool): If True, only log the actions without making changes.
    """
    logger.info("Starting to remove users not in Azure groups...")

    for group_name, members in azure_group_members.items():
        logger.info(f"Processing group: {group_name}")

        if group_name in aws_groups:
            azure_member_names = {member["userPrincipalName"] for member in members}
            aws_member_names = aws_groups[group_name]["Members"]

            logger.debug(
                f"Azure members for group '{group_name}': {azure_member_names}"
            )
            logger.debug(f"AWS members for group '{group_name}': {aws_member_names}")

            members_to_remove = aws_member_names - azure_member_names

            if members_to_remove:
                logger.debug(
                    f"Members to remove from group '{group_name}': {members_to_remove}"
                )
            else:
                logger.debug(f"No members to remove from group '{group_name}'.")

            for username in members_to_remove:
                user_id = get_identity_center_user_id_by_username(
                    identity_center_client, identity_store_id, username
                )

                if user_id:
                    membership_id = get_group_membership_id(
                        identity_center_client,
                        identity_store_id,
                        aws_groups[group_name]["GroupId"],
                        user_id,
                    )

                    if membership_id:
                        if dry_run:
                            logger.info(
                                f"[Dry Run] Would remove user '{username}' from group '{group_name}' in AWS Identity Center."
                            )
                        else:
                            try:
                                logger.info(
                                    f"Removing user '{username}' from group '{group_name}' in AWS Identity Center."
                                )
                                identity_center_client.delete_group_membership(
                                    IdentityStoreId=identity_store_id,
                                    MembershipId=membership_id,
                                )
                                aws_groups[group_name]["Members"].remove(username)
                                logger.info(
                                    f"Successfully removed user '{username}' from group '{group_name}' in AWS Identity Center."
                                )
                            except ClientError as e:
                                logger.error(
                                    f"Error removing user '{username}' from group '{group_name}': {e}"
                                )
                    else:
                        logger.warning(
                            f"No membership ID found for user '{username}' in group '{group_name}'."
                        )
                else:
                    logger.warning(f"No user ID found for username '{username}'.")
        else:
            logger.warning(
                f"Group '{group_name}' not found in AWS Identity Center groups."
            )

    logger.info("Completed removal of users not in Azure groups.")


def delete_orphaned_aws_users(
    identity_center_client, identity_store_id, aws_groups, relevant_users, dry_run
):
    """
    Delete users in AWS Identity Center who are not members of any relevant groups
    and have a specific email type.

    Args:
        identity_center_client: Boto3 client for Identity Center.
        identity_store_id (str): Identity Store ID.
        aws_groups (dict): Existing AWS Identity Center groups.
        relevant_users (set): Set of relevant user IDs.
        dry_run (bool): If True, only log the actions without making changes.
    """
    logger.info("Listing all relevant users in AWS Identity Center...")

    # Create a set of all users who are members of GROUP_PREFIX prefixed groups
    all_group_members = set()
    for group in aws_groups.values():
        all_group_members.update(group["Members"])

    # Iterate over all relevant users
    for user_id in relevant_users:
        try:
            user_info = identity_center_client.describe_user(
                IdentityStoreId=identity_store_id, UserId=user_id
            )
            username = user_info["UserName"]

            # Log user details for debugging
            logger.debug(f"Processing user: {username} with ID: {user_id}")
            logger.debug(f"User's group membership: {username in all_group_members}")

            # Only consider deletion if the user is not a member of any GROUP_PREFIX prefixed group
            if username not in all_group_members:
                email_matches = any(
                    email["Type"] == "EntraId" and email["Primary"]
                    for email in user_info["Emails"]
                )
                logger.debug(
                    f"User {username} has a matching EntraId primary email: {email_matches}"
                )

                if email_matches:
                    if dry_run:
                        logger.info(
                            f"[Dry Run] Would delete user '{username}' from AWS Identity Center."
                        )
                    else:
                        logger.info(
                            f"Deleting user '{username}' from AWS Identity Center."
                        )
                        identity_center_client.delete_user(
                            IdentityStoreId=identity_store_id, UserId=user_id
                        )
                else:
                    logger.debug(
                        f"Skipping deletion for user '{username}' because their email does not match criteria."
                    )
            else:
                logger.debug(
                    f"Skipping deletion for user '{username}' because they are a member of a group."
                )
        except ClientError as e:
            logger.error(f"Error deleting user '{user_id}': {e}")


def lambda_handler(event, context):
    """
    Main handler function for the AWS Lambda function.

    Args:
        event (dict): Event data passed to the function, including the dry_run flag.
        context (object): AWS Lambda context object.

    Returns:
        dict: HTTP response with status code and body.
    """
    dry_run = event.get("dry_run", True)
    sso_client = boto3.client("sso-admin", region_name="eu-west-2")
    identity_center_client = boto3.client("identitystore", region_name="eu-west-2")

    identity_store_id = get_identity_store_id(sso_client)

    try:
        logger.info("Starting the sync process...")
        access_token = get_azure_access_token()
        logger.info("Successfully obtained access token")

        # Get GROUP_PREFIX prefixed groups
        azure_groups = get_entraid_aws_groups(access_token)
        logger.info(f"Found {len(azure_groups)} groups prefixed with '{GROUP_PREFIX}'")

        # Get existing Identity Center groups, users, and their memberships
        aws_groups, relevant_users = get_identity_center_groups_and_relevant_users(
            identity_center_client, identity_store_id, GROUP_PREFIX
        )

        # 1. Add/Sync groups and users between Azure AD and AWS Identity Center
        azure_group_members = sync_azure_groups_with_aws(
            identity_center_client, identity_store_id, aws_groups, azure_groups, dry_run
        )

        # 2. Delete groups in AWS Identity Center that no longer exist in Azure AD
        remove_obsolete_groups(
            identity_center_client,
            identity_store_id,
            aws_groups,
            azure_groups,
            dry_run=dry_run,
        )

        # 3. Remove users from AWS Identity Center groups if they no longer exist in Azure AD groups
        remove_members_not_in_azure_groups(
            identity_center_client,
            identity_store_id,
            aws_groups,
            azure_group_members,
            dry_run=dry_run,
        )

        # 4. Delete users who are not members of any GROUP_PREFIX groups and have the specific email type
        delete_orphaned_aws_users(
            identity_center_client,
            identity_store_id,
            aws_groups,
            relevant_users,
            dry_run=dry_run,
        )

        logger.info("Sync process completed.")
        return {"statusCode": 200, "body": json.dumps({"status": "Completed"})}

    except Exception as e:
        logger.error(f"Error: {str(e)}")
        logger.error(traceback.format_exc())
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}
    finally:
        for handler in logger.handlers:
            handler.flush()


if __name__ == "__main__":
    # This is for local testing
    event = {"dry_run": True}
    context = None
    lambda_handler(event, context)
