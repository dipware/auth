class Challenge:
    id: int = None
    request: str = None
    timestamp_ms: int = None
    user_id: int = None

class Credential:
    id: str = None
    signature_count: int = None
    credential_public_key: str = None
    user_id: int = None

class User:
    id = None
    username = None
    user_handle = None
    credentials: list[Credential] = []
    challenges: list[Challenge] = []
