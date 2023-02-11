async function requestAuthentication() {
    let params = new URLSearchParams();
    let username = document.getElementById('username').value;
    params.append('username', username);
    setStatus('Requesting authentication for username ' + username + '.');
    let response = await post('/login/request', params);
    if (!response.ok) {
        setStatus('Failed to request authentication...');
        throw Error;
    }

    authenticationRequest = await response.json();
    cro = parseRequestOptions(authenticationRequest.requestOptions);
    authenticatingUsername = username;
    assertion = await navigator.credentials.get(cro);
}

function parseRequestOptions(opts) {
    let pOpts = Object.assign({}, opts);
    if ('challenge' in pOpts.publicKey) {
        pOpts.publicKey.challenge = base64decode(opts.publicKey.challenge);
    }

    if ('allowCredentials' in pOpts.publicKey) {
        let allowCredentials = [];
        for (let i = 0; i < pOpts.publicKey.allowCredentials.length; i++) {
            let nCred = Object.assign({}, pOpts.publicKey.allowCredentials[i]);
            nCred.id = base64decode(opts.publicKey.allowCredentials[i].id);
            allowCredentials.push(nCred);
        }

        pOpts.publicKey.allowCredentials = allowCredentials;
    }

    return pOpts;
}

async function assertAuthentication() {
    setStatus('Asserting credential for ' + authenticatingUsername);
    let aJSON = assertionJSON(assertion);
    let params = new URLSearchParams();
    params.append('challengeID', authenticationRequest.challengeID);
    params.append('credential', JSON.stringify(aJSON));
    params.append('username', authenticatingUsername);
    let response = await post('/login/response/', params);
    if (response.ok) {
        setStatus(
            'Successfully authorized username ' + authenticatingUsername + '!');
    } else {
        setStatus(
            'Failed to authorize username ' + authenticatingUsername + '...');
    }
}

async function authenticate() {
    await requestAuthentication();
    await assertAuthentication();
}