import os
import json
import logging
import urllib.request
import urllib.parse
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

# Get IdentityStore ID
def get_identity_store_id(sso_client):
    response = sso_client.list_instances()
    return response['Instances'][0]['IdentityStoreId']

# Get Azure AD token
def get_access_token():
    url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {
        'grant_type': 'client_credentials',
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'scope': 'https://graph.microsoft.com/.default'
    }
    data_encoded = urllib.parse.urlencode(data).encode('utf-8')

    req = urllib.request.Request(url, data=data_encoded, headers=headers)
    with urllib.request.urlopen(req) as response:
        response_data = json.loads(response.read())
        return response_data['access_token']

# Get list of groups prefixed with 'aws_'
def get_aws_prefixed_groups(access_token):
    url = "https://graph.microsoft.com/v1.0/groups"
    headers = {
        'Authorization': f'Bearer {access_token}'
    }
    params = urllib.parse.urlencode({
        '$filter': "startswith(displayName, 'aws_analytical')"
    })

    req = urllib.request.Request(f"{url}?{params}", headers=headers)
    with urllib.request.urlopen(req) as response:
        response_data = json.loads(response.read())
        return response_data['value']

# Get members of a specific group
def get_group_members(access_token, group_id):
    url = f"https://graph.microsoft.com/v1.0/groups/{group_id}/members"
    headers = {
        'Authorization': f'Bearer {access_token}'
    }

    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req) as response:
        response_data = json.loads(response.read())
        return response_data['value']

# Get AWS Identity Center groups
def get_identity_center_groups(identity_center_client, identity_store_id):
    try:
        response = identity_center_client.list_groups(IdentityStoreId=identity_store_id)
        return {group['DisplayName']: group['GroupId'] for group in response['Groups']}
    except ClientError as e:
        logger.error(f"Error listing Identity Center groups: {e}")
        raise e

# Get AWS Identity Center users
def get_identity_center_users(identity_center_client, identity_store_id):
    try:
        response = identity_center_client.list_users(IdentityStoreId=identity_store_id)
        return {user['UserName']: user['UserId'] for user in response['Users']}
    except ClientError as e:
        logger.error(f"Error listing Identity Center users: {e}")
        raise e

# Lambda handler function
def lambda_handler(event, context):
    dry_run = event.get('dry_run', True)
    sso_client = boto3.client('sso-admin', region_name='eu-west-2')
    identity_center_client = boto3.client('identitystore', region_name='eu-west-2')

    identity_store_id = get_identity_store_id(sso_client)

    try:
        access_token = get_access_token()
        logger.info("Successfully obtained access token")

        # Get aws_ prefixed groups
        groups = get_aws_prefixed_groups(access_token)
        logger.info(f"Found {len(groups)} groups prefixed with 'aws_'")

        all_members = []

        # Get existing Identity Center groups and users
        ic_groups = get_identity_center_groups(identity_center_client, identity_store_id)
        ic_users = get_identity_center_users(identity_center_client, identity_store_id)
        # print(ic_users)
        print(len(ic_users))

        # Get members of each group
        for group in groups:
            group_id = group['id']
            group_name = group['displayName']
            members = get_group_members(access_token, group_id)

            if group_name not in ic_groups:
                if dry_run:
                    logger.info(f"[Dry Run] Would create group '{group_name}' in AWS Identity Center.")
                # else:
                #     response = identity_center_client.create_group(IdentityStoreId=IDENTITY_STORE_ID, DisplayName=group_name)
                #     ic_groups[group_name] = response['GroupId']
                #     logger.info(f"Created group '{group_name}' in AWS Identity Center.")

            for member in members:
                member_name = member['userPrincipalName']
                member_given_name = member['givenName']
                member_surname = member['surname']
                if member_name not in ic_users:
                    if dry_run:
                        logger.info(f"[Dry Run] Would create user '{member_name}', '{member_given_name}' in AWS Identity Center.")
                    else:
                        user_response = identity_center_client.create_user(IdentityStoreId=identity_store_id, UserName=member_name, DisplayName=member_name, Name={'FamilyName':member_surname, 'GivenName':member_given_name}, Emails=[{'Value':member_name, 'Type':'Work','Primary':True}])
                        ic_users[member_name] = user_response['UserId']
                        logger.info(f"Created user '{member_name}', '{member_surname}' in AWS Identity Center.")

                membership_data = {
                    'group': group_name,
                    'member_id': member['id'],
                    'member_name': member_name,
                    'member_email': member.get('mail', member_name)
                }
                all_members.append(membership_data)


                # Check if user is already a member of the group
                if dry_run:
                    logger.info(f"[Dry Run] Would add user '{member_name}' to group '{group_name}' in AWS Identity Center.")
                # else:
                #     try:
                #         group_id = ic_groups[group_name]
                #         user_id = ic_users[member_name]
                #         identity_center_client.create_group_membership(IdentityStoreId=IDENTITY_STORE_ID, GroupId=group_id, MemberId=user_id)
                #         logger.info(f"Added user '{member_name}' to group '{group_name}' in AWS Identity Center.")
                #     except ClientError as e:
                #         if e.response['Error']['Code'] == 'EntityAlreadyExistsException':
                #             logger.info(f"User '{member_name}' is already a member of group '{group_name}'.")
                #         else:
                #             raise e

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
