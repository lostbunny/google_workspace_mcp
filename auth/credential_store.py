"""
Credential Store API for Google Workspace MCP

This module provides a standardized interface for credential storage and retrieval,
supporting multiple backends configurable via environment variables.
"""

import os
import json
import logging
import subprocess
from abc import ABC, abstractmethod
from typing import Optional, List
from datetime import datetime
from google.oauth2.credentials import Credentials

logger = logging.getLogger(__name__)


class CredentialStore(ABC):
    """Abstract base class for credential storage."""

    @abstractmethod
    def get_credential(self, user_email: str) -> Optional[Credentials]:
        """
        Get credentials for a user by email.

        Args:
            user_email: User's email address

        Returns:
            Google Credentials object or None if not found
        """
        pass

    @abstractmethod
    def store_credential(self, user_email: str, credentials: Credentials) -> bool:
        """
        Store credentials for a user.

        Args:
            user_email: User's email address
            credentials: Google Credentials object to store

        Returns:
            True if successfully stored, False otherwise
        """
        pass

    @abstractmethod
    def delete_credential(self, user_email: str) -> bool:
        """
        Delete credentials for a user.

        Args:
            user_email: User's email address

        Returns:
            True if successfully deleted, False otherwise
        """
        pass

    @abstractmethod
    def list_users(self) -> List[str]:
        """
        List all users with stored credentials.

        Returns:
            List of user email addresses
        """
        pass


class LocalDirectoryCredentialStore(CredentialStore):
    """Credential store that uses local JSON files for storage."""

    def __init__(self, base_dir: Optional[str] = None):
        """
        Initialize the local JSON credential store.

        Args:
            base_dir: Base directory for credential files. If None, uses the directory
                     configured by environment variables in this order:
                     1. WORKSPACE_MCP_CREDENTIALS_DIR (preferred)
                     2. GOOGLE_MCP_CREDENTIALS_DIR (backward compatibility)
                     3. ~/.google_workspace_mcp/credentials (default)
        """
        if base_dir is None:
            # Check WORKSPACE_MCP_CREDENTIALS_DIR first (preferred)
            workspace_creds_dir = os.getenv("WORKSPACE_MCP_CREDENTIALS_DIR")
            google_creds_dir = os.getenv("GOOGLE_MCP_CREDENTIALS_DIR")

            if workspace_creds_dir:
                base_dir = os.path.expanduser(workspace_creds_dir)
                logger.info(
                    f"Using credentials directory from WORKSPACE_MCP_CREDENTIALS_DIR: {base_dir}"
                )
            # Fall back to GOOGLE_MCP_CREDENTIALS_DIR for backward compatibility
            elif google_creds_dir:
                base_dir = os.path.expanduser(google_creds_dir)
                logger.info(
                    f"Using credentials directory from GOOGLE_MCP_CREDENTIALS_DIR: {base_dir}"
                )
            else:
                home_dir = os.path.expanduser("~")
                if home_dir and home_dir != "~":
                    base_dir = os.path.join(
                        home_dir, ".google_workspace_mcp", "credentials"
                    )
                else:
                    base_dir = os.path.join(os.getcwd(), ".credentials")
                logger.info(f"Using default credentials directory: {base_dir}")

        self.base_dir = base_dir
        logger.info(
            f"LocalDirectoryCredentialStore initialized with base_dir: {base_dir}"
        )

    def _get_credential_path(self, user_email: str) -> str:
        """Get the file path for a user's credentials."""
        if not os.path.exists(self.base_dir):
            os.makedirs(self.base_dir)
            logger.info(f"Created credentials directory: {self.base_dir}")
        return os.path.join(self.base_dir, f"{user_email}.json")

    def get_credential(self, user_email: str) -> Optional[Credentials]:
        """Get credentials from local JSON file."""
        creds_path = self._get_credential_path(user_email)

        if not os.path.exists(creds_path):
            logger.debug(f"No credential file found for {user_email} at {creds_path}")
            return None

        try:
            with open(creds_path, "r") as f:
                creds_data = json.load(f)

            # Parse expiry if present
            expiry = None
            if creds_data.get("expiry"):
                try:
                    expiry = datetime.fromisoformat(creds_data["expiry"])
                    # Ensure timezone-naive datetime for Google auth library compatibility
                    if expiry.tzinfo is not None:
                        expiry = expiry.replace(tzinfo=None)
                except (ValueError, TypeError) as e:
                    logger.warning(f"Could not parse expiry time for {user_email}: {e}")

            credentials = Credentials(
                token=creds_data.get("token"),
                refresh_token=creds_data.get("refresh_token"),
                token_uri=creds_data.get("token_uri"),
                client_id=creds_data.get("client_id"),
                client_secret=creds_data.get("client_secret"),
                scopes=creds_data.get("scopes"),
                expiry=expiry,
            )

            logger.debug(f"Loaded credentials for {user_email} from {creds_path}")
            return credentials

        except (IOError, json.JSONDecodeError, KeyError) as e:
            logger.error(
                f"Error loading credentials for {user_email} from {creds_path}: {e}"
            )
            return None

    def store_credential(self, user_email: str, credentials: Credentials) -> bool:
        """Store credentials to local JSON file."""
        creds_path = self._get_credential_path(user_email)

        creds_data = {
            "token": credentials.token,
            "refresh_token": credentials.refresh_token,
            "token_uri": credentials.token_uri,
            "client_id": credentials.client_id,
            "client_secret": credentials.client_secret,
            "scopes": credentials.scopes,
            "expiry": credentials.expiry.isoformat() if credentials.expiry else None,
        }

        try:
            with open(creds_path, "w") as f:
                json.dump(creds_data, f, indent=2)
            logger.info(f"Stored credentials for {user_email} to {creds_path}")
            return True
        except IOError as e:
            logger.error(
                f"Error storing credentials for {user_email} to {creds_path}: {e}"
            )
            return False

    def delete_credential(self, user_email: str) -> bool:
        """Delete credential file for a user."""
        creds_path = self._get_credential_path(user_email)

        try:
            if os.path.exists(creds_path):
                os.remove(creds_path)
                logger.info(f"Deleted credentials for {user_email} from {creds_path}")
                return True
            else:
                logger.debug(
                    f"No credential file to delete for {user_email} at {creds_path}"
                )
                return True  # Consider it a success if file doesn't exist
        except IOError as e:
            logger.error(
                f"Error deleting credentials for {user_email} from {creds_path}: {e}"
            )
            return False

    def list_users(self) -> List[str]:
        """List all users with credential files."""
        if not os.path.exists(self.base_dir):
            return []

        users = []
        non_credential_files = {"oauth_states"}
        try:
            for filename in os.listdir(self.base_dir):
                if filename.endswith(".json"):
                    user_email = filename[:-5]  # Remove .json extension
                    if user_email in non_credential_files or "@" not in user_email:
                        continue
                    users.append(user_email)
            logger.debug(
                f"Found {len(users)} users with credentials in {self.base_dir}"
            )
        except OSError as e:
            logger.error(f"Error listing credential files in {self.base_dir}: {e}")

        return sorted(users)


class OnePasswordCredentialStore(CredentialStore):
    """
    Read-only credential store backed by 1Password.
    Reads client_id, client_secret, and refresh_token from 1Password at get_credential() time.
    store_credential() is intentionally a no-op — access tokens stay in memory.
    Refresh token writes are handled by the external reauth script.
    """

    def __init__(self):
        self.op_path    = os.environ["OP_PATH"]
        self.vault      = os.environ["OP_VAULT"]
        self.oauth_item = os.environ["OP_OAUTH_ITEM"]
        self.token_item = os.environ["OP_REFRESH_TOKEN_ITEM"]
        self.user_email = os.environ.get("USER_GOOGLE_EMAIL", "")
        logger.info("OnePasswordCredentialStore initialized")

    def _op_item_get(self, item_name: str) -> dict:
        """Fetch all fields from a 1Password item in one subprocess call. Returns {field_id: value}."""
        try:
            result = subprocess.run(
                [self.op_path, "item", "get", item_name, "--vault", self.vault, "--format", "json"],
                capture_output=True, text=True, check=True
            )
            item = json.loads(result.stdout)
            return {f["id"]: f.get("value", "") for f in item.get("fields", []) if f.get("value")}
        except (subprocess.CalledProcessError, FileNotFoundError, json.JSONDecodeError) as e:
            logger.error(f"op item get failed for '{item_name}': {e}")
            return {}

    def get_credential(self, user_email: str) -> Optional[Credentials]:
        oauth_fields  = self._op_item_get(self.oauth_item)
        token_fields  = self._op_item_get(self.token_item)
        client_id     = oauth_fields.get("username")
        client_secret = oauth_fields.get("password")
        refresh_token = token_fields.get("password")
        if not client_id or not client_secret:
            logger.error("OnePasswordCredentialStore: failed to read client_id or client_secret")
            return None
        from datetime import datetime
        creds = Credentials(
            token=None,
            refresh_token=refresh_token,
            token_uri="https://oauth2.googleapis.com/token",
            client_id=client_id,
            client_secret=client_secret,
            expiry=datetime(2000, 1, 1),
        )
        # Eagerly refresh so the credentials are valid before returning.
        # google-auth doesn't populate creds.scopes from the refresh response,
        # so we fetch the authorized scopes from Google's tokeninfo endpoint
        # and set them explicitly. This is the only way to pass the downstream
        # has_required_scopes() check without touching google_auth.py.
        try:
            import urllib.request, json as _json
            from google.auth.transport.requests import Request
            creds.refresh(Request())
            if creds.scopes is None:
                info = _json.loads(urllib.request.urlopen(
                    f"https://oauth2.googleapis.com/tokeninfo?access_token={creds.token}"
                ).read())
                scope_str = info.get("scope", "")
                if scope_str:
                    creds._scopes = frozenset(scope_str.split())
            logger.info(f"OnePasswordCredentialStore: credentials ready, {len(creds._scopes or [])} scopes")
        except Exception as e:
            logger.error(f"OnePasswordCredentialStore: eager refresh failed: {e}")
            return None
        return creds
        logger.info(f"OnePasswordCredentialStore: returning Credentials — expired: {creds.expired}, refresh_token present: {bool(creds.refresh_token)}")
        return creds

    def store_credential(self, user_email: str, credentials: Credentials) -> bool:
        # Access tokens are memory-only. Refresh token writes use the reauth script.
        logger.debug("OnePasswordCredentialStore.store_credential: no-op")
        return True

    def delete_credential(self, user_email: str) -> bool:
        logger.debug("OnePasswordCredentialStore.delete_credential: no-op")
        return True

    def list_users(self) -> List[str]:
        return [self.user_email] if self.user_email else []


# Global credential store instance
_credential_store: Optional[CredentialStore] = None


def get_credential_store() -> CredentialStore:
    """
    Get the global credential store instance.

    Returns:
        Configured credential store instance
    """
    global _credential_store

    if _credential_store is None:
        if os.environ.get("CRED_SOURCE") == "manager":
            _credential_store = OnePasswordCredentialStore()
        else:
            _credential_store = LocalDirectoryCredentialStore()
        logger.info(f"Initialized credential store: {type(_credential_store).__name__}")

    return _credential_store


def set_credential_store(store: CredentialStore):
    """
    Set the global credential store instance.

    Args:
        store: Credential store instance to use
    """
    global _credential_store
    _credential_store = store
    logger.info(f"Set credential store: {type(store).__name__}")
