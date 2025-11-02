#
import base64
import requests
import streamlit as st
from urllib.parse import urlencode

st.set_page_config(page_title="HMRC OAuth Hello World", page_icon="🔐")
st.title("🔐 HMRC Sandbox — Hello World Examples")

# ─────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────
AUTH_URL = "https://test-api.service.hmrc.gov.uk/oauth/authorize"
TOKEN_URL = "https://test-api.service.hmrc.gov.uk/oauth/token"
HELLO_APP_URL = "https://test-api.service.hmrc.gov.uk/hello/application"
HELLO_USER_URL = "https://test-api.service.hmrc.gov.uk/hello/user"

# Your deployed Streamlit app URL (redirect URI)
REDIRECT_URI = "https://apiv4c-4suappsncmpge8jzab3bsh5.streamlit.app/"

# Secrets (set these in Streamlit Cloud → App → Settings → Secrets)
CLIENT_ID = st.secrets["HMRC_CLIENT_ID"]
CLIENT_SECRET = st.secrets["HMRC_CLIENT_SECRET"]

# Keep things between reruns
if "app_access_token" not in st.session_state:
    st.session_state.app_access_token = None
if "user_access_token" not in st.session_state:
    st.session_state.user_access_token = None

# Helper: Basic auth header
def basic_auth_header(client_id: str, client_secret: str) -> str:
    auth_str = f"{client_id}:{client_secret}".encode("utf-8")
    return "Basic " + base64.b64encode(auth_str).decode("utf-8")

# ─────────────────────────────────────────────────────────────
# TAB 1 — Application-restricted (Client Credentials)
# ─────────────────────────────────────────────────────────────
tab1, tab2 = st.tabs(["📦 Hello Application (app-restricted)", "🧑 Hello User (user-restricted)"])

with tab1:
    st.markdown("Calls the **Client Credentials** flow, then `GET /hello/application`.")

    def get_app_token():
        headers = {
            "Authorization": basic_auth_header(CLIENT_ID, CLIENT_SECRET),
            "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
            "Accept": "application/json",
        }
        # HMRC sandbox expects client_id & client_secret in body too
        data = {
            "grant_type": "client_credentials",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        }
        return requests.post(TOKEN_URL, headers=headers, data=data)

    colA, colB = st.columns(2)
    with colA:
        if st.button("Request application access token"):
            resp = get_app_token()
            if resp.status_code == 200:
                token_data = resp.json()
                st.session_state.app_access_token = token_data.get("access_token")
                st.success("Token acquired.")
                st.json(token_data)
            else:
                st.error(f"Token error {resp.status_code}")
                st.code(resp.text)

    with colB:
        if st.button("Call /hello/application", disabled=st.session_state.app_access_token is None):
            headers = {
                "Authorization": f"Bearer {st.session_state.app_access_token}",
                "Accept": "application/vnd.hmrc.1.0+json",
            }
            r = requests.get(HELLO_APP_URL, headers=headers)
            if r.status_code == 200:
                st.success("API call OK")
                st.json(r.json())
            else:
                st.error(f"API error {r.status_code}")
                st.code(r.text)

# ─────────────────────────────────────────────────────────────
# TAB 2 — User-restricted (Authorization Code)
# ─────────────────────────────────────────────────────────────
with tab2:
    st.markdown("""This tab demonstrates the **Authorization Code** flow:

1) Open HMRC login (Sandbox)  
2) Approve the app → HMRC redirects back here with `?code=...`  
3) Exchange `code` for a **user access token**  
4) Call `GET /hello/user`
""")

    # Build the Authorize URL
    # Scope: "hello" is sufficient for Hello User; you can add "openid email" later if needed.
    state = "streamlit-"  # you could randomize this in production
    authorize_params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": "hello",
        "state": state,
    }
    authorize_url = f"{AUTH_URL}?{urlencode(authorize_params)}"

    st.link_button("🔐 Login with HMRC Sandbox (opens new tab)", authorize_url)

    # Check query params for returned "code"
    # Streamlit 1.30+ has st.query_params (dict-like)
    qp = st.query_params
    code = qp.get("code", None)

    if code:
        st.info(f"Authorization code received: {code[:6]}… (truncated)")
        # Exchange code → token
        headers = {
            "Authorization": basic_auth_header(CLIENT_ID, CLIENT_SECRET),
            "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
            "Accept": "application/json",
        }
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            # HMRC sandbox quirk: also include id/secret in body
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        }
        token_resp = requests.post(TOKEN_URL, headers=headers, data=data)
        if token_resp.status_code == 200:
            user_token_data = token_resp.json()
            st.session_state.user_access_token = user_token_data.get("access_token")
            st.success("User access token acquired.")
            st.json(user_token_data)
        else:
            st.error(f"Token exchange error {token_resp.status_code}")
            st.code(token_resp.text)

    st.divider()

    # Call Hello User when we have a user token
    can_call_user = st.session_state.user_access_token is not None
    if st.button("👤 Call /hello/user", disabled=not can_call_user):
        headers = {
            "Authorization": f"Bearer {st.session_state.user_access_token}",
            "Accept": "application/vnd.hmrc.1.0+json",
        }
        r = requests.get(HELLO_USER_URL, headers=headers)
        if r.status_code == 200:
            st.success("Hello User success")
            st.json(r.json())
        else:
            st.error(f"API error {r.status_code}")
            st.code(r.text)

# Footnote
st.caption("Store CLIENT_ID and CLIENT_SECRET in Streamlit Secrets. Redirect URI must exactly match the one configured in HMRC Developer Hub.")