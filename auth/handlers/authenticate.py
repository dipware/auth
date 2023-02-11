import secrets
from jinja2 import Template
from tornado.web import RequestHandler
from webauthn_rp.types import PublicKeyCredentialType
from webauthn_rp.types import PublicKeyCredentialDescriptor
from webauthn_rp.types import PublicKeyCredentialUserEntity, AuthenticatorAttestationResponse
from webauthn_rp.converters import jsonify
from webauthn_rp.parsers import parse_public_key_credential
from dipdb import Memory, Block
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

    def post(self, action):
        if action not in ('request', 'response'):
            self.send_error(403)
            self.finish()
            return
        if action == 'request':
            self._authorisation_request()
        else:
            self._authorisation_response()

    def _authorisation_request(self):
        username = self.get_body_argument('username')

        user_dict = json.loads(Memory.read(Block(f'users/{username}')))
        if user_dict is None:
            return ('User not registered', 400)
        credentials_block = Block(f'users/{username}/credentials')
        credentials_list = json.loads(Memory.read(credentials_block))
        if credentials_list is None:
            return ('User without credential', 400)
        print(f'found credentials: {credentials_list}')

        challenge_bytes = secrets.token_bytes(64)
        challenge = Challenge()
        challenge.request = challenge_bytes
        challenge.timestamp_ms = timestamp_ms()
        challenge.user_id = credentials_list['user']['id']

        challenges_block = Block(f'users/{username}/challenges')
        challenges_list = json.loads(Memory.read(challenges_block))
        challenges_list.append(challenge)
        Memory.update(challenges_block, json.dumps(jsonify(challenges_list)))

        options = CONFIG.APP_CRO_BUILDER.build(
            challenge=challenge_bytes,
            allow_credentials=[
                PublicKeyCredentialDescriptor(
                    id=credential_model,
                    type=PublicKeyCredentialType.PUBLIC_KEY,
                ) for credential_model in credentials_list
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

    def _authorisation_response(self):
        try:
            challengeID = request.form['challengeID']
            credential = parse_public_key_credential(
                json.loads(request.form['credential']))
            username = request.form['username']
        except Exception:
            return ('Could not parse input data', 400)

        if type(credential.response) is not AuthenticatorAssertionResponse:
            return ('Invalid response type', 400)

        challenge_model = Challenge.query.filter_by(id=challengeID).first()
        if not challenge_model:
            return ('Could not find challenge matching given id', 400)

        user_model = User.query.filter_by(username=username).first()
        if not user_model:
            return ('Invalid username', 400)

        current_timestamp = timestamp_ms()
        if current_timestamp - challenge_model.timestamp_ms > CONFIG.APP_TIMEOUT:
            return ('Timeout', 408)

        user_entity = PublicKeyCredentialUserEntity(name=username,
                                                    id=user_model.user_handle,
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

