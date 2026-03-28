#!/usr/bin/env python3
"""One-time setup (and reauth): store google-workspace-mcp credentials in Linux keyring."""
import getpass
import keyring

SERVICE = "google-workspace-mcp"
EMAIL   = "njmoyer@gmail.com"


def main():
    print("google-workspace-mcp Linux Keyring Setup")
    print("Credentials are stored in the system keyring — never written to disk.\n")

    client_id     = input("Google OAuth Client ID: ").strip()
    client_secret = getpass.getpass("Google OAuth Client Secret: ")
    refresh_token = getpass.getpass("Google Refresh Token: ")

    keyring.set_password(SERVICE, "client_id",                    client_id)
    keyring.set_password(SERVICE, "client_secret",                client_secret)
    keyring.set_password(SERVICE, f"refresh_token:{EMAIL}",       refresh_token)

    print("\nCredentials stored in keyring successfully.")


if __name__ == "__main__":
    main()
