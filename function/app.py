import os
import json
import logging
import requests
import boto3
from botocore.exceptions import ClientError
import sys
import traceback

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# Initialize environment variables
TENANT_ID = os.environ.get('AZURE_TENANT_ID')
CLIENT_ID = os.environ.get('AZURE_CLIENT_ID')
CLIENT_SECRET = os.environ.get('AZURE_CLIENT_SECRET')

# Cache for storing user and group data
user_cache = {}
group_members_cache = {}

def get_identity_store_id(sso_client):
    response = sso_client.list_instances()
    return response['Instances'][0]['IdentityStoreId']

def get_azure_access_token():
    url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    data = {
        'grant_type': 'client_credentials',
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'scope': 'https://graph.microsoft.com/.default'
    }

    response = requests.post(url, headers=headers, data=data)
    response.raise_for_status()
    return response.json()['access_token']

def get_entraid_aws_groups(access_token):
    url = "https://graph.microsoft.com/v1.0/groups"
    headers = {'Authorization': f'Bearer {access_token}'}
    params = {'$filter': "startswith(displayName, 'entraid-aws-identitycenter-')"}

    response = requests.get(url, headers=headers, params=params)
    response.raise_for_status()
    return response.json()['value']

def get_entraid_group_members(access_token, group_id):
    if group_id in group_members_cache:
        return group_members_cache[group_id]

    headers = {'Authorization': f'Bearer {access_token}'}

    # Fetch members
    url_members = f"https://graph.microsoft.com/v1.0/groups/{group_id}/members"
    response_members = requests.get(url_members, headers=headers)
    response_members.raise_for_status()
    members = response_members.json()['value']

    # Fetch admins
    url_admins = f"https://graph.microsoft.com/v1.0/groups/{group_id}/owners"
    response_admins = requests.get(url_admins, headers=headers)
    response_admins.raise_for_status()
    admins = response_admins.json()['value']

    # Combine members and admins
    combined_members = members + admins

    group_members_cache[group_id] = combined_members
    return combined_members

def get_identity_center_groups_and_relevant_users(identity_center_client, identity_store_id, group_name_prefix=""):
    try:
        logger.info("Fetching AWS Identity Center groups and their memberships...")
        groups = {}
        relevant_users = set()

        paginator = identity_center_client.get_paginator('list_groups')
        for page in paginator.paginate(IdentityStoreId=identity_store_id):
            for group in page['Groups']:
                if group_name_prefix == "" or group['DisplayName'].startswith(group_name_prefix):
                    groups[group['DisplayName']] = {
                        'GroupId': group['GroupId'],
                        'Members': set()
                    }

        for group_name, group_info in groups.items():
            logger.info(f"Fetching members for group: {group_name}")
            paginator = identity_center_client.get_paginator('list_group_memberships')
            for page in paginator.paginate(IdentityStoreId=identity_store_id, GroupId=group_info['GroupId']):
                for membership in page['GroupMemberships']:
                    user_id = membership['MemberId']['UserId']
                    username = get_identity_center_username(identity_center_client, identity_store_id, user_id)
                    if username:
                        group_info['Members'].add(username)
                        relevant_users.add(user_id)

        logger.info(f"Number of Identity Center groups retrieved with prefix '{group_name_prefix}': {len(groups)}")
        return groups, relevant_users
    except ClientError as e:
        logger.error(f"Error listing Identity Center groups and memberships: {e}")
        raise e

def get_identity_center_username(identity_center_client, identity_store_id, user_id):
    if user_id in user_cache:
        return user_cache[user_id]

    try:
        logger.info(f"Fetching username for user ID: {user_id}")
        response = identity_center_client.describe_user(
            IdentityStoreId=identity_store_id,
            UserId=user_id
        )
        username = response.get('UserName')
        if username:
            user_cache[user_id] = username
        return username
    except ClientError as e:
        logger.error(f"Error getting username for user ID {user_id}: {e}")
        return None

def get_group_membership_id(identity_center_client, identity_store_id, group_id, user_id):
    try:
        logger.info(f"Fetching membership ID for user {user_id} in group {group_id}")
        paginator = identity_center_client.get_paginator('list_group_memberships')
        for page in paginator.paginate(IdentityStoreId=identity_store_id, GroupId=group_id):
            for membership in page['GroupMemberships']:
                if membership['MemberId']['UserId'] == user_id:
                    return membership['MembershipId']
    except ClientError as e:
        logger.error(f"Error getting membership ID for user ID {user_id} in group ID {group_id}: {e}")
    return None

def delete_unused_groups(identity_center_client, identity_store_id, aws_groups, azure_groups, dry_run=True):
    azure_group_names = set(group['displayName'] for group in azure_groups)
    for group_name in list(aws_groups.keys()):
        if group_name not in azure_group_names:
            if dry_run:
                logger.info(f"[Dry Run] Would delete group '{group_name}' from AWS Identity Center.")
            else:
                group_id = aws_groups[group_name]['GroupId']
                try:
                    logger.info(f"Deleting group '{group_name}' from AWS Identity Center.")
                    identity_center_client.delete_group(IdentityStoreId=identity_store_id, GroupId=group_id)
                    del aws_groups[group_name]
                except ClientError as e:
                    logger.error(f"Error deleting group {group_name}: {e}")

def remove_users_not_in_azure(access_token, identity_center_client, identity_store_id, aws_groups, azure_groups, dry_run=True):
    for group in azure_groups:
        group_name = group['displayName']
        if group_name in aws_groups:
            azure_member_names = {member['userPrincipalName'] for member in get_entraid_group_members(access_token, group['id'])}
            aws_member_names = aws_groups[group_name]['Members']
            members_to_remove = aws_member_names - azure_member_names

            for username in members_to_remove:
                user_id = get_identity_center_user_id_by_username(identity_center_client, identity_store_id, username)
                if user_id:
                    membership_id = get_group_membership_id(identity_center_client, identity_store_id, aws_groups[group_name]['GroupId'], user_id)
                    if membership_id:
                        if dry_run:
                            logger.info(f"[Dry Run] Would remove user '{username}' from group '{group_name}' in AWS Identity Center.")
                        else:
                            try:
                                logger.info(f"Removing user '{username}' from group '{group_name}' in AWS Identity Center.")
                                identity_center_client.delete_group_membership(
                                    IdentityStoreId=identity_store_id,
                                    MembershipId=membership_id
                                )
                                aws_groups[group_name]['Members'].remove(username)
                            except ClientError as e:
                                logger.error(f"Error removing user '{username}' from group '{group_name}': {e}")

def get_identity_center_user_id_by_username(identity_center_client, identity_store_id, username):
    if username in user_cache:
        return user_cache[username]

    try:
        logger.info(f"Fetching user ID for username: {username}")
        response = identity_center_client.list_users(
            IdentityStoreId=identity_store_id,
            Filters=[{'AttributePath': 'UserName', 'AttributeValue': username}]
        )
        if response['Users']:
            user_id = response['Users'][0]['UserId']
            user_cache[username] = user_id
            return user_id
    except ClientError as e:
        logger.error(f"Error getting user ID for username {username}: {e}")
    return None

def delete_unused_users(identity_center_client, identity_store_id, aws_groups, relevant_users, dry_run=True):
    logger.info("Listing all relevant users in AWS Identity Center...")

    # Create a set of all users who are members of entraid-aws-identitycenter- prefixed groups
    all_group_members = set()
    for group in aws_groups.values():
        all_group_members.update(group['Members'])

    # Iterate over all relevant users
    for user_id in relevant_users:
        try:
            user_info = identity_center_client.describe_user(
                IdentityStoreId=identity_store_id,
                UserId=user_id
            )
            username = user_info['UserName']

            # Only consider deletion if the user is not a member of any entraid-prefixed group
            if username not in all_group_members:
                if any(email['Type'] == 'EntraId' and email['Primary'] for email in user_info['Emails']):
                    if dry_run:
                        logger.info(f"[Dry Run] Would delete user '{username}' from AWS Identity Center.")
                    else:
                        logger.info(f"Deleting user '{username}' from AWS Identity Center.")
                        identity_center_client.delete_user(
                            IdentityStoreId=identity_store_id,
                            UserId=user_id
                        )
        except ClientError as e:
            logger.error(f"Error deleting user '{user_id}': {e}")

# Lambda handler function
def lambda_handler(event, context):
    dry_run = event.get('dry_run', True)
    sso_client = boto3.client('sso-admin', region_name='eu-west-2')
    identity_center_client = boto3.client('identitystore', region_name='eu-west-2')

    identity_store_id = get_identity_store_id(sso_client)

    try:
        logger.info("Starting the sync process...")
        access_token = get_azure_access_token()
        logger.info("Successfully obtained access token")

        # Get entraid-aws-identitycenter- prefixed groups
        azure_groups = get_entraid_aws_groups(access_token)
        logger.info(f"Found {len(azure_groups)} groups prefixed with 'entraid-aws-identitycenter-'")

        # Get existing Identity Center groups, users, and their memberships
        aws_groups, relevant_users = get_identity_center_groups_and_relevant_users(identity_center_client, identity_store_id, "entraid-aws-identitycenter-")

        # 1. Delete groups in AWS Identity Center that no longer exist in Azure AD
        delete_unused_groups(identity_center_client, identity_store_id, aws_groups, azure_groups, dry_run=dry_run)

        # 2. Remove users from AWS Identity Center groups if they no longer exist in Azure AD groups
        remove_users_not_in_azure(access_token, identity_center_client, identity_store_id, aws_groups, azure_groups, dry_run=dry_run)

        # 3. Add/Sync groups and users between Azure AD and AWS Identity Center
        for group in azure_groups:
            group_name = group['displayName']
            group_id = group['id']
            members = get_entraid_group_members(access_token, group_id)

            if group_name not in aws_groups:
                if dry_run:
                    logger.info(f"[Dry Run] Would create group '{group_name}' in AWS Identity Center.")
                    aws_groups[group_name] = {
                        'GroupId': f"dry_run_dummy_'{group_name}'",
                        'Members': set()
                    }
                else:
                    response = identity_center_client.create_group(IdentityStoreId=identity_store_id, DisplayName=group_name)
                    aws_groups[group_name] = {
                        'GroupId': response['GroupId'],
                        'Members': set()
                    }
                    logger.info(f"Created group '{group_name}' in AWS Identity Center.")

            # Sync members (including admins)
            group_info = aws_groups[group_name]
            for member in members:
                member_name = member['userPrincipalName']
                member_given_name = member['givenName']
                member_surname = member['surname']

                logger.info(f"Processing member: {member_name}, GivenName: {member_given_name}, Surname: {member_surname}")

                if member_name not in group_info['Members']:
                    if dry_run:
                        logger.info(f"[Dry Run] Would add user '{member_name}' to group '{group_name}' in AWS Identity Center.")
                    else:
                        try:
                            # Create the user if not existing
                            user_id = get_identity_center_user_id_by_username(identity_center_client, identity_store_id, member_name)
                            if not user_id:
                                user_response = identity_center_client.create_user(
                                    IdentityStoreId=identity_store_id,
                                    UserName=member_name,
                                    DisplayName=member_name,
                                    Name={'FamilyName': member_surname, 'GivenName': member_given_name},
                                    Emails=[{'Value': member_name, 'Type': 'EntraId', 'Primary': True}]
                                )
                                user_id = user_response['UserId']
                            # Add the user to the group
                            identity_center_client.create_group_membership(
                                IdentityStoreId=identity_store_id,
                                GroupId=group_info['GroupId'],
                                MemberId={'UserId': user_id}
                            )
                            group_info['Members'].add(member_name)
                            logger.info(f"Added user '{member_name}' to group '{group_name}' in AWS Identity Center.")
                        except ClientError as e:
                            if e.response['Error']['Code'] == 'EntityAlreadyExistsException':
                                logger.info(f"User '{member_name}' is already a member of group '{group_name}'.")
                            else:
                                raise e

        # 4. Delete users who are not members of any entraid-aws-identitycenter- groups and have the specific email type
        delete_unused_users(identity_center_client, identity_store_id, aws_groups, relevant_users, dry_run=dry_run)

        logger.info("Sync process completed.")
        return {
            'statusCode': 200,
            'body': json.dumps({"status": "Completed"})
        }

    except Exception as e:
        logger.error(f"Error: {str(e)}")
        logger.error(traceback.format_exc())
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }
    finally:
        for handler in logger.handlers:
            handler.flush()

if __name__ == "__main__":
    # This is for local testing
    event = {"dry_run": True}
    context = None
    lambda_handler(event, context)

