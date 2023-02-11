from webauthn_rp.types import PublicKeyCredentialRpEntity, \
    PublicKeyCredentialParameters, PublicKeyCredentialType, \
    COSEAlgorithmIdentifier
from webauthn_rp.builders import CredentialCreationOptionsBuilder, \
    CredentialRequestOptionsBuilder
from webauthn_rp.backends import CredentialsBackend

from auth.models.registrar import RegistrarImpl

PORT=60428
APP_ORIGIN = f'http://localhost:{PORT}'
APP_TIMEOUT = 60000
APP_RELYING_PARTY = PublicKeyCredentialRpEntity(name='localhost',
                                                id='localhost')

APP_CCO_BUILDER = CredentialCreationOptionsBuilder(
    rp=APP_RELYING_PARTY,
    pub_key_cred_params=[
        PublicKeyCredentialParameters(type=PublicKeyCredentialType.PUBLIC_KEY,
                                      alg=COSEAlgorithmIdentifier.Value.ES256)
    ],
    timeout=APP_TIMEOUT,
)

APP_CRO_BUILDER = CredentialRequestOptionsBuilder(
    rp_id=APP_RELYING_PARTY.id,
    timeout=APP_TIMEOUT,
)

APP_CREDENTIALS_BACKEND = CredentialsBackend(RegistrarImpl())
