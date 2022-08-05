# Copyright 2017-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file
# except in compliance with the License. A copy of the License is located at
#
#     http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an "AS IS"
# BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under the License.

from classifier import varDump
from rest_api_utils import compose_rest_response

import json
import time
import urllib.request
from jose import jwk, jwt
from jose.utils import base64url_decode

print('JWT Decode Lambda Cold Start')

region = "us-west-1"
user_pool_id = "us-west-1_jqN0WLASK"
app_client_id = "4qv8m44mllqllljbenbeou4uis"
keys_url = f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}/.well-known/jwks.json"

# Download keys from Cognito IDP
with urllib.request.urlopen(keys_url) as f:
  response = f.read()
keys = json.loads(response.decode('utf-8'))['keys']

varDump(keys, 'Keys downloaded from Cognito idp website')


def lambda_handler(event, context):

    #varDump(event, 'lambda_handler entry: display event')

    if event.get('body') != None:
        body = json.loads(event['body'])
    else:
        # body not sent improperly formed request
        return compose_rest_response('400', '', 'BAD REQUEST')
    
    if body.get('idToken') != None:
        token = body['idToken']
    else:
        # token not sent, improperly formed request
        return compose_rest_response('400', '', 'BAD REQUEST')

    # get the kid from the headers prior to verification
    headers = jwt.get_unverified_headers(token)
    kid = headers['kid']

    # search for the kid in the downloaded public keys
    key_index = -1
    for i in range(len(keys)):
        if kid == keys[i]['kid']:
            key_index = i
            break

    if key_index == -1:
        print('Public key not found in jwks.json')
        # use 422 for all checks that fail
        #(https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/422
        return compose_rest_response('422', '', 'PUBLIC KEY NOT FOUND')

    # construct the public key
    public_key = jwk.construct(keys[key_index])

    # get the last two sections of the token,
    # message and signature (encoded in base64)
    message, encoded_signature = str(token).rsplit('.', 1)

    # decode the signature
    decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))

    # verify the signature
    if not public_key.verify(message.encode("utf8"), decoded_signature):
        print('Signature verification failed')
        return compose_rest_response('422', '', 'SIGNATURE VERIFICATION FAILED')
    
    print('Signature successfully verified')

    # signature verification complete, check expiration dates
    # and audience claim matches the App Id.
    claims = jwt.get_unverified_claims(token)

    if time.time() > claims['exp']:
        print('Token is expired')
        return compose_rest_response('422', '', 'TOKEN EXPIRED')

    # and the Audience  (use claims['client_id'] if verifying an access token)
    if claims['aud'] != app_client_id:
        print('Token was not issued for this AWS App')
        return compose_rest_response('422', '', 'AUDIENCE MISMATCH')

    # after audience is verified to match AWS client id, we can trust the claims
    # and use them for our purposes.
    if claims.get('cognito:username') != None:

        response_body = {'username': claims['cognito:username']}
        return compose_rest_response('200', json.dumps(response_body), 'OK')

    else:

        return compose_rest_response('422', '', 'USERNAME UNAVAILABLE')
