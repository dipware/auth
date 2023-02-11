async function post(endpoint, params) {
  return fetch('http://localhost:' + 60428 + endpoint, {
    credentials: 'include',
    body: params,
    method: 'POST',
  });
}

function base64encode(src) {
  let buffer = (src instanceof ArrayBuffer) ? src : src.buffer;
  return btoa(
    Array.from(new Uint8Array(buffer)).map(
      x => String.fromCodePoint(x)).join('')
  );
}

function base64decode(s) {
  return new Uint8Array(Array.from(atob(s)).map(x => x.charCodeAt(0)));
}

function setStatus(s) {
  let statusElement = document.getElementById('status');
  statusElement.innerText = s;
}