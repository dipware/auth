import secrets
from jinja2 import Template
from tornado.web import RequestHandler
from webauthn_rp.types import AuthenticatorAssertionResponse, PublicKeyCredentialType
from webauthn_rp.types import PublicKeyCredentialDescriptor
from webauthn_rp.types import PublicKeyCredentialUserEntity
from webauthn_rp.converters import jsonify
from webauthn_rp.parsers import parse_public_key_credential
from dipdb import Memory, Block, Find
from auth.models.user import Challenge, Credential, User
from auth import config as CONFIG
from ..utils import timestamp_ms
import json
class AuthenticationHandler(RequestHandler):

    template: Template = None
    def initialize(self, template):
        '''
        self: A request has appeared!
        '''
        self.template = template

    def get(self):
        self.write(self.template.render())
        self.finish()

    async def post(self, action):
        if action not in ('request', 'response'):
            self.send_error(403)
            self.finish()
            return
        if action == 'request':
            self._login_request()
        else:
            self._login_response()

    def _login_request(self):
        username = self.get_body_argument('username')

        user_dict = json.loads(Memory.read(Block(f'users/{username}')))
        if user_dict is None:
            return ('User not registered', 400)
        credentials_block = Block(f'users/{username}/credentials/').path.iterdir()
        credentials_list = []
        for credentials in credentials_block:

            credentials_list.append(json.loads(Memory.read(Block('/'.join(credentials.parts[1:])))))
            
        if len(credentials_list) == 0:
            return ('User without credential', 400)
        print(f'found credentials: {credentials_list}')

        challenge_bytes = secrets.token_bytes(64)
        challenge = Challenge()
        challenge.id = 1
        challenge.request = challenge_bytes
        challenge.timestamp_ms = timestamp_ms()
        challenge.user_id = user_dict['id']

        challenges_block = Block(f'users/{username}/challenges')
        challenges_list = json.loads(Memory.read(challenges_block))
        challenges_list.append(challenge)
        Memory.update(challenges_block, json.dumps(jsonify(challenges_list)))

        # credentials_list_send = []
        # for credential in credentials_list:
        #     cred = Credential()
        #     cred.id = credential['id']
        #     cred.credential_public_key = credential['credentialPublicKey']
        #     cred.signature_count = credential['signatureCount']
        #     cred.user_id = user_dict['id']
        #     credentials_list_send.append()
        options = CONFIG.APP_CRO_BUILDER.build(
            challenge=challenge_bytes,
            allow_credentials=[
                PublicKeyCredentialDescriptor(
                    id=credential['id'],
                    type=PublicKeyCredentialType.PUBLIC_KEY,
                ) for credential in credentials_list
            ])

        options_json = jsonify(options)
        response_json = {
            'challengeID': challenge.id,
            'requestOptions': options_json,
        }

        response_json_string = json.dumps(response_json)
        self.write(response_json_string)
        self.finish()

        # return (response_json_string, 200, {'Content-Type': 'application/json'})

    def _login_response(self):
        try:
            challengeID = self.get_body_argument('challengeID')
            credential = parse_public_key_credential(
                json.loads(self.get_body_argument('credential')))
            username = self.get_body_argument('username')
        except Exception:
            return ('Could not parse input data', 400)

        if type(credential.response) is not AuthenticatorAssertionResponse:
            return ('Invalid response type', 400)

        challenge_model = None
        challenges_list = json.loads(Find.read(Block(f'users/{username}/challenges')))
        for challenge in challenges_list:
            if challenge['id'] == challengeID:
                challenge_model = Challenge()
                challenge_model.id = int(challenge['id'])
                challenge_model.request = challenge['request']
                challenge_model.timestamp_ms = int(challenge['timestampMs'])
                challenge_model.user_id = int(challenge['userId'])
        if challenge_model == None:
            return ('Could not find challenge matching given id', 400)

        user_model = json.loads(Find.read(Block(f'users/{username}')))
        if not user_model:
            return ('Invalid username', 400)

        current_timestamp = timestamp_ms()
        if current_timestamp - challenge_model.timestamp_ms > CONFIG.APP_TIMEOUT:
            return ('Timeout', 408)

        user_entity = PublicKeyCredentialUserEntity(name=username,
                                                    id=user_model['userHandle'],
                                                    display_name=username)

        try:
            CONFIG.APP_CREDENTIALS_BACKEND.handle_credential_assertion(
                credential=credential,
                user=user_entity,
                rp=CONFIG.APP_RELYING_PARTY,
                expected_challenge=challenge_model.request,
                expected_origin=CONFIG.APP_ORIGIN)
        except Exception:
            return ('Could not handle credential assertion', 400)

        return ('Success', 200)

