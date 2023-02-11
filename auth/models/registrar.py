import base64
import json
import os
from dipdb import Memory, Block, Find
from webauthn_rp.types import PublicKeyCredential, AttestationObject, \
                                AttestationType , PublicKeyCredentialUserEntity, \
                                PublicKeyCredentialRpEntity, \
                                TrustedPath, AuthenticatorData \
                                
from webauthn_rp.converters import cose_key
from webauthn_rp.parsers import parse_cose_key
from webauthn_rp.registrars import CredentialsRegistrar, CredentialData
from auth.models.user import Credential, User
from typing import Any, Optional
from webauthn_rp.converters import jsonify
import re
from ..utils import get_shortened_bytestring

class RegistrarImpl(CredentialsRegistrar):
    def register_credential_attestation(
            self,
            credential: PublicKeyCredential,
            att: AttestationObject,
            att_type: AttestationType,
            user: PublicKeyCredentialUserEntity,
            rp: PublicKeyCredentialRpEntity,
            trusted_path: Optional[TrustedPath] = None) -> Any:
        assert att.auth_data is not None
        assert att.auth_data.attested_credential_data is not None
        cpk = att.auth_data.attested_credential_data.credential_public_key
        print('REGISTRAAAAAWRR')
        user_model = json.loads(Memory.read(Block(f'users/{user.display_name}')))
        if user_model is None: return 'No user found'
        username = user_model['username']
        print(user_model)
        credential_model = Credential()
        credential_model.id = credential.raw_id
        credential_model.signature_count = None
        credential_model.credential_public_key = cose_key(cpk)
        credential_model.user = user_model

        credentials_block = Block(f'users/{username}/credentials/{get_shortened_bytestring(credential_model.id)}')
        Memory.create(credentials_block)
        Memory.update(credentials_block, json.dumps(jsonify(credential_model)))
        print('saved credentials to database jkeklolmao!')

    def register_credential_assertion(self, credential: PublicKeyCredential,
                                      authenticator_data: AuthenticatorData,
                                      user: PublicKeyCredentialUserEntity,
                                      rp: PublicKeyCredentialRpEntity) -> Any:
        credentials_block = Block(f'users/{user.display_name}/credentials/{get_shortened_bytestring(credential.raw_id)}')
        credentials_model = jsonify(Memory.read(credentials_block))
        credentials_model['signature_count'] = authenticator_data.sign_count
        Memory.update(credentials_block, json.dumps(jsonify(credentials_model)))

    def get_credential_data(self,
                            credential_id: bytes) -> Optional[CredentialData]:
        search_string = 'users/*/credentials/' + get_shortened_bytestring(credential_id)
        credentials_block = Block(search_string)
        credential_model = json.loads(Find.read(credentials_block))
        print(credential_model)
        if credential_model is None:
            return None
        return CredentialData(
            parse_cose_key(credential_model.credential_public_key),
            credential_model.signature_count,
            PublicKeyCredentialUserEntity(
                name=credential_model.user.username,
                id=credential_model.user.user_handle,
                display_name=credential_model.user.username))
