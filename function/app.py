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

# Get list of groups prefixed with 'entraid-aws-identitycenter-'
def get_entraid_aws_groups(access_token):
    """
    Retrieves Azure AD groups with names prefixed with 'entraid-aws-identitycenter-'.

    Args:
        access_token (str): Azure AD access token.

    Returns:
        list: List of groups.
    """
    url = "https://graph.microsoft.com/v1.0/groups"
    headers = {'Authorization': f'Bearer {access_token}'}
    params = {'$filter': "startswith(displayName, 'entraid-aws-identitycenter-')"}

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

# Get AWS Identity Center groups and their memberships
def get_identity_center_groups_and_members(identity_center_client, identity_store_id, group_name_prefix=""):
    """
    Retrieves AWS Identity Center groups and their memberships using a paginator.

    Args:
        identity_center_client: Boto3 Identity Store client.
        identity_store_id (str): Identity Store ID.
        group_name_prefix (str): Prefix to filter group names by.

    Returns:
        dict: Dictionary mapping group display names to their details and memberships (usernames).
    """
    try:
        groups = {}
        paginator = identity_center_client.get_paginator('list_groups')
        page_iterator = paginator.paginate(IdentityStoreId=identity_store_id)

        for page in page_iterator:
            for group in page['Groups']:
                if group_name_prefix == "" or group['DisplayName'].startswith(group_name_prefix):
                    groups[group['DisplayName']] = {
                        'GroupId': group['GroupId'],
                        'Members': set()
                    }

        for group_name, group_info in groups.items():
            paginator = identity_center_client.get_paginator('list_group_memberships')
            page_iterator = paginator.paginate(IdentityStoreId=identity_store_id, GroupId=group_info['GroupId'])

            for page in page_iterator:
                for membership in page['GroupMemberships']:
                    user_id = membership['MemberId']['UserId']
                    # Fetch the username for each user and add it to the members set
                    username = get_identity_center_username(identity_center_client, identity_store_id, user_id)
                    if username:
                        group_info['Members'].add(username)

        logger.info(f"Number of Identity Center groups retrieved with prefix '{group_name_prefix}': {len(groups)}")
        return groups
    except ClientError as e:
        logger.error(f"Error listing Identity Center groups and memberships: {e}")
        raise e

def get_identity_center_username(identity_center_client, identity_store_id, user_id):
    """
    Retrieves the username for a given user ID from AWS Identity Center.

    Args:
        identity_center_client: Boto3 Identity Store client.
        identity_store_id (str): Identity Store ID.
        user_id (str): User ID.

    Returns:
        str: Username or None if the user is not found.
    """
    try:
        response = identity_center_client.describe_user(
            IdentityStoreId=identity_store_id,
            UserId=user_id
        )
        return response.get('UserName')
    except ClientError as e:
        logger.error(f"Error getting username for user ID {user_id}: {e}")
        return None

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

        # Get entraid-aws-identitycenter- prefixed groups
        groups = get_entraid_aws_groups(access_token)
        logger.info(f"Found {len(groups)} groups prefixed with 'entraid-aws-identitycenter-'")

        all_members = []

        # Get existing Identity Center groups, users, and their memberships
        ic_groups = get_identity_center_groups_and_members(identity_center_client, identity_store_id, "entraid-aws-identitycenter-")

        # Process each group
        for group in groups:
            group_id = group['id']
            group_name = group['displayName']
            members = get_entraid_group_members(access_token, group_id)

            if group_name not in ic_groups:
                if dry_run:
                    logger.info(f"[Dry Run] Would create group '{group_name}' in AWS Identity Center.")
                else:
                    response = identity_center_client.create_group(IdentityStoreId=identity_store_id, DisplayName=group_name)
                    ic_groups[group_name] = {
                        'GroupId': response['GroupId'],
                        'Members': set()
                    }
                    logger.info(f"Created group '{group_name}' in AWS Identity Center.")

            # Process each member in the group
            for member in members:
                member_name = member['userPrincipalName']
                member_given_name = member['givenName']
                member_surname = member['surname']

                # Log user details for troubleshooting
                logger.info(f"Processing member: {member_name}, GivenName: {member_given_name}, Surname: {member_surname}")

                # Check if the user is already a member of the group before adding
                group_info = ic_groups[group_name]
                if member_name not in group_info['Members']:
                    if dry_run:
                        logger.info(f"[Dry Run] Would add user '{member_name}' to group '{group_name}' in AWS Identity Center.")
                    else:
                        try:
                            # Create the user if not existing
                            user_response = identity_center_client.create_user(
                                IdentityStoreId=identity_store_id,
                                UserName=member_name,
                                DisplayName=member_name,
                                Name={'FamilyName': member_surname, 'GivenName': member_given_name},
                                Emails=[{'Value': member_name, 'Type': 'EntraId', 'Primary': True}]
                            )
                            group_info['Members'].add(member_name)
                            logger.info(f"Added user '{member_name}' to group '{group_name}' in AWS Identity Center.")
                        except ClientError as e:
                            if e.response['Error']['Code'] == 'EntityAlreadyExistsException':
                                logger.info(f"User '{member_name}' is already a member of group '{group_name}'.")
                            else:
                                raise e

                # Example membership data structure
                membership_data = {
                    'group': group_name,
                    'member_id': member['id'],
                    'member_name': member_name,
                    'member_email': member.get('mail', member_name)
                }
                all_members.append(membership_data)

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
