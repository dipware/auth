function parseCreationOptions(opts) {
    let pOpts = Object.assign({}, opts);
    if ('challenge' in pOpts.publicKey) {
        pOpts.publicKey.challenge = base64decode(opts.publicKey.challenge);
    }

    if ('user' in pOpts.publicKey && 'id' in pOpts.publicKey.user) {
        pOpts.publicKey.user.id = base64decode(opts.publicKey.user.id);
    }

    return pOpts;
}


async function registerUsername() {
    let params = new URLSearchParams();
    let username = document.getElementById('username').value;
    params.append('username', username);
    setStatus('Registering username ' + username + '.');
    let response = await post('/register/request', params);
    if (!response.ok) {
        setStatus('Failed to register username...could already be registered.');
        throw Error;
    }

    registrationRequest = await response.json();
    cco = parseCreationOptions(registrationRequest.creationOptions);
    registeredUsername = username;
    setStatus('Creating credential for ' + username + '.');
    attestation = await navigator.credentials.create(cco);
}

function attestationJSON(cred) {
    let credJSON = {};
    credJSON.type = cred.type;
    credJSON.id = cred.id;
    credJSON.rawId = base64encode(cred.rawId);
    credJSON.response = {
        attestationObject: base64encode(cred.response.attestationObject),
        clientDataJSON: base64encode(cred.response.clientDataJSON),
    };
    return credJSON;
}


async function registerAttestation() {
    setStatus('Attesting credential for ' + registeredUsername + '.');
    let attJSON = attestationJSON(attestation);
    let params = new URLSearchParams();
    params.append('challengeID', registrationRequest.challengeID);
    params.append('credential', JSON.stringify(attJSON));
    params.append('username', registeredUsername);
    let response = await post('/register/response', params);
    if (response.ok) {
        setStatus(
            'Successfully registered credential for ' + registeredUsername + '!');
    } else {
        setStatus(
            'Failed to register credential for ' + registeredUsername + '...');
    }
}

async function register() {
    console.log('hi')
    await registerUsername();
    await registerAttestation();
}