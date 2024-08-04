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

# Initialise environment variables
TENANT_ID = os.environ.get('AZURE_TENANT_ID')
CLIENT_ID = os.environ.get('AZURE_CLIENT_ID')
CLIENT_SECRET = os.environ.get('AZURE_CLIENT_SECRET')

# Get IdentityStore ID
def get_identity_store_id(sso_client):
    """
    Retrieves the Identity Store ID from the AWS SSO client.

    Args:
        sso_client: Boto3 SSO client.

    Returns:
        str: Identity Store ID.
    """
    response = sso_client.list_instances()
    return response['Instances'][0]['IdentityStoreId']

# Get Azure AD token
def get_azure_access_token():
    """
    Fetches an OAuth 2.0 token from Azure AD using client credentials.

    Returns:
        str: Access token.
    """
    url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    data = {
        'grant_type': 'client_credentials',
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'scope': 'https://graph.microsoft.com/.default'
    }

    response = requests.post(url, headers=headers, data=data)
    response.raise_for_status()  # Raises an error for bad responses
    response_data = response.json()
    return response_data['access_token']

# Get list of groups prefixed with 'aws_analytical'
def get_entraid_aws_groups(access_token):
    """
    Retrieves Azure AD groups with names prefixed with 'aws_analytical'.

    Args:
        access_token (str): Azure AD access token.

    Returns:
        list: List of groups.
    """
    url = "https://graph.microsoft.com/v1.0/groups"
    headers = {'Authorization': f'Bearer {access_token}'}
    params = {'$filter': "startswith(displayName, 'aws_analytical')"}

    response = requests.get(url, headers=headers, params=params)
    response.raise_for_status()
    response_data = response.json()
    return response_data['value']

# Get members of a specific group
def get_entraid_group_members(access_token, group_id):
    """
    Retrieves members of a specific Azure AD group.

    Args:
        access_token (str): Azure AD access token.
        group_id (str): Group ID.

    Returns:
        list: List of group members.
    """
    url = f"https://graph.microsoft.com/v1.0/groups/{group_id}/members"
    headers = {'Authorization': f'Bearer {access_token}'}

    response = requests.get(url, headers=headers)
    response.raise_for_status()
    response_data = response.json()
    return response_data['value']

# Get AWS Identity Center groups with paginator
def get_identity_center_groups(identity_center_client, identity_store_id):
    """
    Retrieves AWS Identity Center groups using a paginator.

    Args:
        identity_center_client: Boto3 Identity Store client.
        identity_store_id (str): Identity Store ID.

    Returns:
        dict: Dictionary mapping group display names to group IDs.
    """
    try:
        paginator = identity_center_client.get_paginator('list_groups')
        page_iterator = paginator.paginate(IdentityStoreId=identity_store_id)
        groups = {}
        for page in page_iterator:
            for group in page['Groups']:
                groups[group['DisplayName']] = group['GroupId']
        logger.info(f"Number of Identity Center groups retrieved: {len(groups)}")
        return groups
    except ClientError as e:
        logger.error(f"Error listing Identity Center groups: {e}")
        raise e

# Get AWS Identity Center users with paginator
def get_identity_center_users(identity_center_client, identity_store_id):
    """
    Retrieves AWS Identity Center users using a paginator.

    Args:
        identity_center_client: Boto3 Identity Store client.
        identity_store_id (str): Identity Store ID.

    Returns:
        dict: Dictionary mapping usernames to user IDs.
    """
    try:
        paginator = identity_center_client.get_paginator('list_users')
        page_iterator = paginator.paginate(IdentityStoreId=identity_store_id)
        users = {}
        for page in page_iterator:
            for user in page['Users']:
                users[user['UserName']] = user['UserId']
        logger.info(f"Number of Identity Center Users Retrieved: {len(users)}")
        return users
    except ClientError as e:
        logger.error(f"Error listing Identity Center users: {e}")
        raise e

# Get the user ID from the username
def get_identity_center_user_id(identity_center_client, identity_store_id, username):
    """
    Retrieves the user ID for a given username from AWS Identity Center.

    Args:
        identity_center_client: Boto3 Identity Store client.
        identity_store_id (str): Identity Store ID.
        username (str): Username.

    Returns:
        str: User ID or None if the user is not found.
    """
    try:
        response = identity_center_client.list_users(
            IdentityStoreId=identity_store_id,
            Filters=[{'AttributePath': 'UserName', 'AttributeValue': username}]
        )
        if response['Users']:
            return response['Users'][0]['UserId']
        else:
            logger.error(f"User {username} not found in Identity Center.")
            return None
    except ClientError as e:
        logger.error(f"Error getting user ID for {username}: {e}")
        raise e

# Lambda handler function
def lambda_handler(event, context):
    """
    Main Lambda function handler.

    Args:
        event (dict): Event data passed to the function.
        context (object): Runtime information.

    Returns:
        dict: Response containing status code and body with the results.
    """
    dry_run = event.get('dry_run', True)
    sso_client = boto3.client('sso-admin', region_name='eu-west-2')
    identity_center_client = boto3.client('identitystore', region_name='eu-west-2')

    identity_store_id = get_identity_store_id(sso_client)

    try:
        access_token = get_azure_access_token()
        logger.info("Successfully obtained access token")

        # Get aws_ prefixed groups
        groups = get_entraid_aws_groups(access_token)
        logger.info(f"Found {len(groups)} groups prefixed with 'aws_analytical'")

        all_members = []

        # Get existing Identity Center groups and users
        ic_groups = get_identity_center_groups(identity_center_client, identity_store_id)
        ic_users = get_identity_center_users(identity_center_client, identity_store_id)

        # Get members of each group
        for group in groups:
            group_id = group['id']
            group_name = group['displayName']
            members = get_entraid_group_members(access_token, group_id)

            if group_name not in ic_groups:
                if dry_run:
                    logger.info(f"[Dry Run] Would create group '{group_name}' in AWS Identity Center.")
                else:
                    response = identity_center_client.create_group(IdentityStoreId=identity_store_id, DisplayName=group_name)
                    ic_groups[group_name] = response['GroupId']
                    logger.info(f"Created group '{group_name}' in AWS Identity Center.")

            for member in members:
                member_name = member['userPrincipalName']
                member_given_name = member['givenName']
                member_surname = member['surname']

                # Log user details for troubleshooting
                logger.info(f"Processing member: {member_name}, GivenName: {member_given_name}, Surname: {member_surname}")

                if member_name not in ic_users:
                    if dry_run:
                        logger.info(f"[Dry Run] Would create user '{member_name}', '{member_given_name}' in AWS Identity Center.")
                    else:
                        user_response = identity_center_client.create_user(
                            IdentityStoreId=identity_store_id,
                            UserName=member_name,
                            DisplayName=member_name,
                            Name={'FamilyName': member_surname, 'GivenName': member_given_name},
                            Emails=[{'Value': member_name, 'Type': 'EntraId', 'Primary': True}]
                        )
                        ic_users[member_name] = user_response['UserId']
                        logger.info(f"Created user '{member_name}', '{member_surname}' in AWS Identity Center.")

                membership_data = {
                    'group': group_name,
                    'member_id': member['id'],
                    'member_name': member_name,
                    'member_email': member.get('mail', member_name)
                }
                all_members.append(membership_data)

                if dry_run:
                    logger.info(f"[Dry Run] Would add user '{member_name}' to group '{group_name}' in AWS Identity Center.")
                else:
                    try:
                        group_id = ic_groups[group_name]
                        user_id = get_identity_center_user_id(identity_center_client, identity_store_id, member_name)
                        if user_id:
                            identity_center_client.create_group_membership(
                                IdentityStoreId=identity_store_id,
                                GroupId=group_id,
                                MemberId={'UserId': user_id}
                            )
                            logger.info(f"Added user '{member_name}' to group '{group_name}' in AWS Identity Center.")
                    except ClientError as e:
                        if e.response['Error']['Code'] == 'EntityAlreadyExistsException':
                            logger.info(f"User '{member_name}' is already a member of group '{group_name}'.")
                        else:
                            raise e

        return {
            'statusCode': 200,
            'body': json.dumps(all_members)
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
