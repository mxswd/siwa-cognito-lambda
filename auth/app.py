from ast import AsyncFunctionDef
import json
import boto3
from botocore.exceptions import ClientError
import jwt
import requests
import datetime
from jwt import PyJWKClient
import os

ssm_client = boto3.client('ssm')

TEAM_ID = ssm_client.get_parameter(Name='/prod/auth/siwa/teamid',
                                        WithDecryption=True)['Parameter']['Value']
SIWA_SUB = ssm_client.get_parameter(Name='/prod/auth/siwa/sub',
                                        WithDecryption=True)['Parameter']['Value']
JWT_SECRET = ssm_client.get_parameter(Name='/prod/auth/siwa/keysecret',
                                        WithDecryption=True)['Parameter']['Value']
SIWA_KEYID = ssm_client.get_parameter(Name='/prod/auth/siwa/keyid',
                                        WithDecryption=True)['Parameter']['Value']

COG_USERPOOLID = ssm_client.get_parameter(Name='/prod/auth/cognito/userpool',
                                        WithDecryption=True)['Parameter']['Value']
COG_CLIENT_ID = ssm_client.get_parameter(Name='/prod/auth/cognito/clientid',
                                        WithDecryption=True)['Parameter']['Value']

client = boto3.client('cognito-idp')

def lambda_handler(event, context):
    request_type = event['queryStringParameters']['request']
    
    code = json.loads(event['body'])['token']
    if request_type == "auth":
        return make_auth_request(code)
    elif request_type == "refresh":
        return make_refresh(code)
    else:
        return {
            "statusCode": 400,
            "body": "invalid request",
        }

def make_refresh(code):
    response = client.admin_initiate_auth(
        UserPoolId=COG_USERPOOLID,
        ClientId=COG_CLIENT_ID,
        AuthFlow='REFRESH_TOKEN_AUTH',
        AuthParameters = {
            'REFRESH_TOKEN': code,
        }
    )

    return {
        "statusCode": response['ResponseMetadata']['HTTPStatusCode'],
        "body": json.dumps(response['AuthenticationResult']),
    }

def make_auth_request(code):
    client_secret = '-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----'.format(JWT_SECRET)
    client_secret_token = jwt.encode(
        {
            'iss': TEAM_ID,
            'iat': datetime.datetime.utcnow(),
            'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=300),
            'aud': 'https://appleid.apple.com',
            'sub': SIWA_SUB
        },
        client_secret,
        headers = {'kid': SIWA_KEYID},
        algorithm = "ES256"
    )
    
    r = requests.post("https://appleid.apple.com/auth/token", data = { 'client_secret' : client_secret_token, 'client_id': SIWA_SUB, 'code': code, 'grant_type': 'authorization_code' })
    
    apple_token = json.loads(r.text)['id_token']
    jwks_client = PyJWKClient("https://appleid.apple.com/auth/keys")
    signing_key = jwks_client.get_signing_key_from_jwt(apple_token)
    data = jwt.decode(apple_token, signing_key.key, algorithms=["RS256"], audience=SIWA_SUB, issuer="https://appleid.apple.com")
    
    # FIXME: validate the c_hash, or at_hash?
    # https://sarunw.com/posts/sign-in-with-apple-3/#how-to-verify-the-token
    # https://sarunw.com/posts/sign-in-with-apple-4/
    
    # {'iss': 'https://appleid.apple.com', 'aud': 'domain here', 'exp': 1661642699, 'iat': 1661556299, 'sub': 'subject here', 'at_hash': 'hash here', 'email': 'email here', 'email_verified': 'true', 'auth_time': 1661556293, 'nonce_supported': True}

    email = data['email']
    username = 'signinwithapple_{}'.format(data['sub'])

    try:
        existing_user = client.admin_get_user(Username = username, UserPoolId = COG_USERPOOLID)
        if existing_user:
            # user exists, all good.
            if existing_user['Enabled'] == True:
                # user enabled, ok
                ()
            else:
                raise Exception("user disabled")
    except ClientError as err:
        if err.response['Error']['Code'] == 'UserNotFoundException':
            # Create the user, this is rate limited, so we need to admin_get_user first.
            create_response = client.admin_create_user(
                UserPoolId=COG_USERPOOLID,
                Username=username,
                MessageAction='SUPPRESS',
                UserAttributes = [{
                    'Name': 'email',
                    'Value': email
                }]
            )
        else:
            raise err

    response = client.admin_initiate_auth(
        UserPoolId=COG_USERPOOLID,
        ClientId=COG_CLIENT_ID,
        AuthFlow='CUSTOM_AUTH',
        AuthParameters = {
            'USERNAME': username,
        }
    )

    return {
        "statusCode": response['ResponseMetadata']['HTTPStatusCode'],
        "body": json.dumps(response['AuthenticationResult']),
    }