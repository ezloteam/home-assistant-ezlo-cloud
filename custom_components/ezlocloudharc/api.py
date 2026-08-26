"""Ezlo HA Cloud integration API for Home Assistant.

Each public function returns a typed dataclass on success and raises a typed
exception on failure — no `{success, data, error}` envelopes. The HTTP
sessions are obtained from Home Assistant via `get_async_client(hass)` so the
integration satisfies the `inject-websession` quality-scale rule.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
from dataclasses import dataclass
from typing import Any, TypedDict

import httpx
from homeassistant.core import HomeAssistant
from homeassistant.helpers.httpx_client import get_async_client

from .const import DEFAULT_API_URI
from .exceptions import (
    EzloApiUnexpectedResponseError,
    EzloApiUnreachableError,
    EzloAuthError,
    EzloMissingUUIDError,
)

_LOGGER = logging.getLogger(__name__)


def _auth_api_url(api_uri: str) -> str:
    return f"{api_uri}/api/auth"


def _api_url(api_uri: str) -> str:
    return f"{api_uri}/api"


# ── Typed payloads ───────────────────────────────────────────────────


class UserDict(TypedDict, total=False):
    """Authenticated-user fields returned by login/signup."""

    uuid: str
    username: str
    email: str
    ezlo_id: int | str
    oem_id: int


@dataclass(slots=True)
class AuthResult:
    """Result of a successful login or signup call."""

    token: str
    tunnel_token: str | None
    user: UserDict
    subscription_status: str | None
    is_trial: bool
    payment_required: bool
    trial_ends_at: str | None
    checkout_url: str | None


@dataclass(slots=True)
class SubscriptionStatusResult:
    """Result of fetching the live subscription status from the backend.

    subscribe_url is set by the backend when the user has no active
    subscription and can self-serve — it points at the central Ezlo
    subscribe flow, pre-filled with the user's email.
    """

    status: str
    is_active: bool
    is_trial: bool
    trial_ends_at: str
    subscribe_url: str


# ── HTTP helpers ─────────────────────────────────────────────────────


def _extract_error_message(response: httpx.Response) -> str:
    """Pull a human-readable error message from an HTTP error response."""
    try:
        body = response.json()
    except (ValueError, json.JSONDecodeError):
        return response.text
    if isinstance(body, dict):
        for key in ("error", "message"):
            value = body.get(key)
            if isinstance(value, str):
                return value
    return response.text


def _classify_status_error(error: httpx.HTTPStatusError) -> EzloAuthError | None:
    """Return an EzloAuthError if the HTTP status indicates auth failure.

    409 is the backend's ``device_already_bound`` answer (this Home Assistant
    instance is bound to a different account). It is surfaced as an auth
    error so the flows run it through ``classify_login_error`` and show the
    dedicated message instead of a generic "unexpected response".
    """
    if error.response.status_code in (401, 403, 409):
        return EzloAuthError(_extract_error_message(error.response))
    return None


# ── Authentication ──────────────────────────────────────────────────


async def authenticate(
    hass: HomeAssistant,
    username: str,
    password: str,
    ha_instance_id: str,
    *,
    api_uri: str = DEFAULT_API_URI,
) -> AuthResult:
    """Authenticate against the Ezlo Cloud auth API.

    Raises:
        EzloAuthError: credentials rejected or backend returned 4xx auth error.
        EzloApiUnreachableError: network failure.
        EzloApiUnexpectedResponseError: malformed response from the API.
        EzloMissingUUIDError: token returned but UUID claim missing.
    """
    payload = {
        "username": username,
        "password": password,
        "oem_id": "1",
        "ha_instance_id": ha_instance_id,
    }

    client = get_async_client(hass)
    try:
        response = await client.post(
            f"{_auth_api_url(api_uri)}/login", json=payload, timeout=10
        )
        response.raise_for_status()
    except httpx.HTTPStatusError as err:
        auth_err = _classify_status_error(err)
        if auth_err is not None:
            raise auth_err from err
        raise EzloApiUnexpectedResponseError(_extract_error_message(err.response)) from err
    except httpx.HTTPError as err:
        raise EzloApiUnreachableError(str(err)) from err

    try:
        data = response.json()
    except (ValueError, json.JSONDecodeError) as err:
        raise EzloApiUnexpectedResponseError(str(err)) from err

    _LOGGER.debug("Login response keys: %s", sorted(data) if isinstance(data, dict) else type(data).__name__)

    token = data.get("token") if isinstance(data, dict) else None
    if not token:
        message = data.get("error") if isinstance(data, dict) else None
        raise EzloAuthError(message or "Invalid credentials")

    try:
        jwt_payload = decode_jwt_payload(token)
    except (ValueError, binascii.Error, json.JSONDecodeError) as err:
        raise EzloApiUnexpectedResponseError(f"Invalid JWT: {err}") from err

    user_uuid = jwt_payload.get("uuid")
    if not user_uuid:
        raise EzloMissingUUIDError("UUID missing in token payload")

    return AuthResult(
        token=token,
        tunnel_token=data.get("tunnel_token"),
        user=UserDict(
            uuid=user_uuid,
            username=jwt_payload.get("username", username),
            email=jwt_payload.get("email", ""),
            ezlo_id=jwt_payload.get("ezlo_user_id", ""),
            oem_id=1,
        ),
        subscription_status=data.get("subscription_status"),
        is_trial=bool(data.get("is_trial", False)),
        payment_required=bool(data.get("payment_required", False)),
        trial_ends_at=data.get("trial_ends_at"),
        checkout_url=data.get("checkout_url"),
    )


async def signup(
    hass: HomeAssistant,
    username: str,
    email: str,
    password: str,
    ha_instance_id: str,
    *,
    api_uri: str = DEFAULT_API_URI,
) -> AuthResult:
    """Register a new account against the Ezlo Cloud auth API.

    Raises:
        EzloAuthError: backend rejected the signup (e.g. username taken).
        EzloApiUnreachableError: network failure.
        EzloApiUnexpectedResponseError: malformed response from the API.
        EzloMissingUUIDError: token returned but UUID claim missing.
    """
    payload = {
        "username": username,
        "password": password,
        "email": email,
        "ha_instance_id": ha_instance_id,
    }

    client = get_async_client(hass)
    try:
        response = await client.post(
            f"{_auth_api_url(api_uri)}/signup", json=payload, timeout=10
        )
        response.raise_for_status()
    except httpx.HTTPStatusError as err:
        auth_err = _classify_status_error(err)
        if auth_err is not None:
            raise auth_err from err
        raise EzloAuthError(_extract_error_message(err.response)) from err
    except httpx.HTTPError as err:
        raise EzloApiUnreachableError(str(err)) from err

    try:
        data = response.json()
    except (ValueError, json.JSONDecodeError) as err:
        raise EzloApiUnexpectedResponseError(str(err)) from err

    token = data.get("token") if isinstance(data, dict) else None
    if not token:
        message = data.get("message") if isinstance(data, dict) else None
        raise EzloAuthError(message or "Signup failed")

    try:
        jwt_payload = decode_jwt_payload(token)
    except (ValueError, binascii.Error, json.JSONDecodeError) as err:
        raise EzloApiUnexpectedResponseError(f"Invalid JWT: {err}") from err

    user_uuid = jwt_payload.get("uuid")
    if not user_uuid:
        raise EzloMissingUUIDError("UUID missing in token payload")

    return AuthResult(
        token=token,
        tunnel_token=data.get("tunnel_token"),
        user=UserDict(
            uuid=user_uuid,
            username=username,
            email=email,
            ezlo_id=jwt_payload.get("ezlo_user_id", ""),
        ),
        subscription_status=data.get("subscription_status", ""),
        is_trial=bool(data.get("is_trial", False)),
        payment_required=bool(data.get("payment_required", True)),
        trial_ends_at=data.get("trial_ends_at"),
        checkout_url=data.get("checkout_url"),
    )


async def logout(
    hass: HomeAssistant,
    *,
    auth_token: str,
    api_uri: str = DEFAULT_API_URI,
) -> bool:
    """Tell the backend this instance is logging out.

    Releases the server-side binding between this Home Assistant instance and
    the account (so a different account can log in on this box) and revokes
    the tunnel token. Best-effort: the local logout must never be blocked by
    the backend, so every failure is logged and reported as ``False`` rather
    than raised.
    """
    client = get_async_client(hass)
    try:
        response = await client.post(
            f"{_auth_api_url(api_uri)}/logout",
            headers={"Authorization": f"Bearer {auth_token}"},
            timeout=5,
        )
        response.raise_for_status()
    except httpx.HTTPStatusError as err:
        # 401 = token already invalid, 404 = older backend without the route:
        # nothing to release in either case.
        _LOGGER.debug(
            "Backend logout returned %s: %s",
            err.response.status_code,
            _extract_error_message(err.response),
        )
        return False
    except httpx.HTTPError as err:
        _LOGGER.debug("Backend logout unreachable: %s", err)
        return False
    return True


# ── Subscription status ─────────────────────────────────────────────


async def get_subscription_status(
    hass: HomeAssistant,
    user_uuid: str,
    *,
    auth_token: str,
    api_uri: str = DEFAULT_API_URI,
) -> SubscriptionStatusResult:
    """Fetch the live subscription status for the authenticated user.

    The backend resolves the user from the Bearer token; ``user_uuid`` is
    still sent as a query parameter for compatibility with older servers
    and must be the uuid embedded in ``auth_token``.

    Raises:
        EzloAuthError: the token was rejected (401/403) — re-login needed.
        EzloApiUnreachableError: network failure.
        EzloApiUnexpectedResponseError: bad response shape or missing data.
    """
    client = get_async_client(hass)
    try:
        response = await client.get(
            f"{_api_url(api_uri)}/subscription/status",
            params={"user_uuid": user_uuid},
            headers={"Authorization": f"Bearer {auth_token}"},
            timeout=5,
        )
        response.raise_for_status()
    except httpx.HTTPStatusError as err:
        if (auth_err := _classify_status_error(err)) is not None:
            raise auth_err from err
        raise EzloApiUnexpectedResponseError(
            f"http_{err.response.status_code}: {_extract_error_message(err.response)}"
        ) from err
    except httpx.HTTPError as err:
        raise EzloApiUnreachableError(str(err)) from err

    try:
        payload = response.json()
    except (ValueError, json.JSONDecodeError) as err:
        raise EzloApiUnexpectedResponseError(str(err)) from err

    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict):
        raise EzloApiUnexpectedResponseError("No subscription data returned")

    return SubscriptionStatusResult(
        status=str(data.get("status", "unknown")),
        is_active=bool(data.get("is_active", False)),
        is_trial=bool(data.get("is_trial", False)),
        trial_ends_at=str(data.get("trial_ends_at", "") or ""),
        subscribe_url=str(data.get("subscribe_url", "") or ""),
    )


# ── JWT helpers ─────────────────────────────────────────────────────


def decode_jwt_payload(token: str) -> dict[str, Any]:
    """Decode a JWT token and return its payload as a dictionary.

    Raises:
        ValueError: invalid JWT format.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")

    payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
    decoded: dict[str, Any] = json.loads(base64.urlsafe_b64decode(payload_b64))
    return decoded
