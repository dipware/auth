import base64
import json
import secrets
import time
from jinja2 import Template
from tornado.web import RequestHandler
from webauthn_rp.types import PublicKeyCredentialUserEntity, AuthenticatorAttestationResponse
from webauthn_rp.converters import jsonify
from webauthn_rp.parsers import parse_public_key_credential
from auth.models.user import Challenge, User
from auth import config as CONFIG
from webauthn_rp.utils import url_base64_decode

from dipdb import Memory, Block
from auth.utils import timestamp_ms

class RegistrationHandler(RequestHandler):
    template: Template = None
    def initialize(self, template):
        '''
        self: A request has appeared!
        '''
        self.template = template

    def get(self):
        print(self.request.remote_ip)
        if self.request.remote_ip not in ('127.0.0.1', '::1'):
            self.send_error(403)
        self.write(self.template.render())

    def post(self, action):
        if self.request.remote_ip not in ('127.0.0.1', '::1'):
            self.send_error(403)
        if action not in ('request', 'response'):
            self.send_error(403)
            self.finish()
            return
        if action == 'request':
            self._registration_request()
        else:
            self._registration_response()

    def _registration_request(self):
        user = User()
        user.username = self.get_body_argument('username')
        block = Block(f'users/{user.username}')
        if block.path.exists():
            self.send_error(409)
            return
        user.id = 0
        user.user_handle = secrets.token_bytes(64)

        challenge = Challenge()
        challenge.id = 0
        challenge.request = secrets.token_bytes(64)
        challenge.timestamp_ms = int(time.time() * 1000)
        challenge.user_id = user.id

        user.challenges.append(challenge)
        challenges_block = Block(f'users/{user.username}/challenges')
        challenges = json.dumps(jsonify(user.challenges))
        Memory.create(block)
        Memory.update(block, json.dumps(jsonify(user.__dict__)))
        Memory.create(challenges_block)
        Memory.update(challenges_block, challenges)
        options = CONFIG.APP_CCO_BUILDER.build(
            user=PublicKeyCredentialUserEntity(name=user.username,
                                            id=user.user_handle,
                                            display_name=user.username),
            challenge=challenge.request,
        )
        options_json = jsonify(options)
        response_json = {
            'challengeID': challenge.id,
            'creationOptions': options_json,
        }

        response_json_string = json.dumps(response_json)
        self.write(response_json_string)
        self.finish()
        # return (response_json_string, 200, {'Content-Type': 'application/json'})

    def _registration_response(self):
        try:
            challengeID = self.get_body_argument('challengeID')
            credential = parse_public_key_credential(
                json.loads(self.get_body_argument('credential')))
            username = self.get_body_argument('username')
        except Exception:
            return ('Could not parse input data', 400)

        if type(credential.response) is not AuthenticatorAttestationResponse:
            return ('Invalid response type', 400)

        user_json_str = Memory.read(Block('users/%s' % username))
        user_challenges_json_str = Memory.read(Block('users/%s/challenges' % username))
        user_json = json.loads(user_json_str)
        if not user_json:
            return ('Invalid username', 400)
        user_challenges = json.loads(user_challenges_json_str)
        # user = User.parse(user_json)
        user = User()
        user.id = user_json['id']
        user.username = user_json['username']
        user.user_handle = user_json['userHandle']
        user.challenges = user_challenges
        challenge = user.challenges[0]

        if not challenge:
            return ('Could not find challenge matching given id', 400)

        current_timestamp = timestamp_ms()
        if current_timestamp - challenge['timestampMs'] > CONFIG.APP_TIMEOUT:
            return ('Timeout', 408)

        user_entity = PublicKeyCredentialUserEntity(name=username,
                                                    id=user.user_handle,
                                                    display_name=username)

        try:
            CONFIG.APP_CREDENTIALS_BACKEND.handle_credential_attestation(
                credential=credential,
                user=user_entity,
                rp=CONFIG.APP_RELYING_PARTY,
                expected_challenge=url_base64_decode(challenge['request']),
                expected_origin=CONFIG.APP_ORIGIN)
        except Exception as e:
            self.set_status(400)
            raise e

        self.set_status(200)
        self.finish()