#!/usr/bin/env python3
"""
Automated OAuth flow to obtain a refresh token and store it in the Linux keyring.

Reads client_id and client_secret from the keyring, opens the browser for Google
consent, catches the callback on localhost:8080, exchanges the code for tokens,
and stores the refresh_token in the keyring.

Usage:
    cd ~/CopilotHome/repos/google_workspace_mcp
    uv run python scripts/get-refresh-token.py
"""
import http.server
import json
import threading
import urllib.parse
import urllib.request
import webbrowser

import keyring

SERVICE = "google-workspace-mcp"
EMAIL   = "njmoyer@gmail.com"
REDIRECT_URI = "http://localhost:8080"
TOKEN_URI    = "https://oauth2.googleapis.com/token"
AUTH_URI      = "https://accounts.google.com/o/oauth2/v2/auth"

SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/calendar",
    "https://www.googleapis.com/auth/contacts",
    "https://www.googleapis.com/auth/contacts.other.readonly",
]


def main():
    client_id     = keyring.get_password(SERVICE, "client_id")
    client_secret = keyring.get_password(SERVICE, "client_secret")
    if not client_id or not client_secret:
        print("ERROR: client_id or client_secret not found in keyring.")
        print("Run setup-linux-keyring.py first.")
        return

    # Build authorization URL
    params = urllib.parse.urlencode({
        "client_id":     client_id,
        "redirect_uri":  REDIRECT_URI,
        "response_type": "code",
        "scope":         " ".join(SCOPES),
        "access_type":   "offline",
        "prompt":        "consent",
        "login_hint":    EMAIL,
    })
    auth_url = f"{AUTH_URI}?{params}"

    # Holder for the authorization code
    auth_code = {}
    server_ready = threading.Event()

    class CallbackHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            query = urllib.parse.urlparse(self.path).query
            qs = urllib.parse.parse_qs(query)
            code = qs.get("code", [None])[0]
            error = qs.get("error", [None])[0]

            if error:
                self.send_response(400)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(f"<h1>Error: {error}</h1>".encode())
                auth_code["error"] = error
            elif code:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<h1>Success! You can close this tab.</h1>")
                auth_code["code"] = code
            else:
                self.send_response(400)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<h1>No code received.</h1>")

        def log_message(self, format, *args):
            pass  # suppress request logging

    server = http.server.HTTPServer(("localhost", 8080), CallbackHandler)
    server.timeout = 120  # 2 minute timeout

    def serve():
        server_ready.set()
        server.handle_request()  # handle exactly one request

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    server_ready.wait()

    print(f"Opening browser for Google OAuth consent...")
    print(f"If the browser doesn't open, visit:\n{auth_url}\n")
    webbrowser.open(auth_url)

    thread.join(timeout=130)
    server.server_close()

    if "error" in auth_code:
        print(f"Authorization failed: {auth_code['error']}")
        return
    if "code" not in auth_code:
        print("No authorization code received (timed out).")
        return

    # Exchange authorization code for tokens
    print("Exchanging authorization code for tokens...")
    data = urllib.parse.urlencode({
        "code":          auth_code["code"],
        "client_id":     client_id,
        "client_secret": client_secret,
        "redirect_uri":  REDIRECT_URI,
        "grant_type":    "authorization_code",
    }).encode()

    req = urllib.request.Request(TOKEN_URI, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")

    try:
        resp = urllib.request.urlopen(req)
        tokens = json.loads(resp.read())
    except Exception as e:
        print(f"Token exchange failed: {e}")
        return

    refresh_token = tokens.get("refresh_token")
    if not refresh_token:
        print("WARNING: No refresh_token in response. Token exchange returned:")
        print(json.dumps({k: v for k, v in tokens.items() if k != "access_token"}, indent=2))
        return

    keyring.set_password(SERVICE, f"refresh_token:{EMAIL}", refresh_token)
    print(f"\nRefresh token stored in keyring for {EMAIL}.")
    print("google-workspace-mcp is ready to use.")


if __name__ == "__main__":
    main()
