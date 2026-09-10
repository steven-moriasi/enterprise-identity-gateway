const configuration = {
  authorizationEndpoint:
    "http://localhost:8080/realms/enterprise/protocol/openid-connect/auth",
  tokenEndpoint:
    "http://localhost:8080/realms/enterprise/protocol/openid-connect/token",
  clientId: "command-center",
  redirectUri: "http://localhost:3000/",
  gatewayUrl: "http://localhost:8000",
};

const output = document.querySelector("#output");
const loginButton = document.querySelector("#login");
const profileButton = document.querySelector("#profile");
const resourcesButton = document.querySelector("#resources");
let accessToken = null;
let tenantId = null;

function base64Url(bytes) {
  return btoa(String.fromCharCode(...bytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

async function sha256(value) {
  return new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)),
  );
}

function randomValue() {
  return base64Url(crypto.getRandomValues(new Uint8Array(32)));
}

async function beginLogin() {
  const verifier = randomValue();
  const state = randomValue();
  sessionStorage.setItem("pkce_verifier", verifier);
  sessionStorage.setItem("oauth_state", state);
  const parameters = new URLSearchParams({
    client_id: configuration.clientId,
    redirect_uri: configuration.redirectUri,
    response_type: "code",
    scope: "openid profile email resources:read",
    code_challenge: base64Url(await sha256(verifier)),
    code_challenge_method: "S256",
    state,
  });
  window.location.assign(`${configuration.authorizationEndpoint}?${parameters}`);
}

async function completeLogin() {
  const parameters = new URLSearchParams(window.location.search);
  const code = parameters.get("code");
  if (!code) {
    return;
  }
  const state = parameters.get("state");
  const expectedState = sessionStorage.getItem("oauth_state");
  const verifier = sessionStorage.getItem("pkce_verifier");
  if (!state || state !== expectedState || !verifier) {
    throw new Error("OAuth callback state is invalid.");
  }
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: configuration.clientId,
    redirect_uri: configuration.redirectUri,
    code,
    code_verifier: verifier,
  });
  const response = await fetch(configuration.tokenEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  if (!response.ok) {
    throw new Error("Token exchange failed.");
  }
  const tokens = await response.json();
  accessToken = tokens.access_token;
  sessionStorage.removeItem("oauth_state");
  sessionStorage.removeItem("pkce_verifier");
  window.history.replaceState({}, document.title, "/");
  loginButton.disabled = true;
  profileButton.disabled = false;
  resourcesButton.disabled = false;
  output.textContent = "Signed in. Load the validated profile.";
}

async function gatewayRequest(path) {
  const response = await fetch(`${configuration.gatewayUrl}${path}`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  const body = await response.json();
  if (!response.ok) {
    throw new Error(body.detail || "Gateway request failed.");
  }
  return body;
}

profileButton.addEventListener("click", async () => {
  try {
    const profile = await gatewayRequest("/api/me");
    tenantId = profile.tenant_id;
    output.textContent = JSON.stringify(profile, null, 2);
  } catch (error) {
    output.textContent = error.message;
  }
});

resourcesButton.addEventListener("click", async () => {
  try {
    if (!tenantId) {
      const profile = await gatewayRequest("/api/me");
      tenantId = profile.tenant_id;
    }
    const resources = await gatewayRequest(`/api/tenants/${tenantId}/resources`);
    output.textContent = JSON.stringify(resources, null, 2);
  } catch (error) {
    output.textContent = error.message;
  }
});

loginButton.addEventListener("click", beginLogin);
completeLogin().catch((error) => {
  output.textContent = error.message;
});
