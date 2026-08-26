"""Ezlo HA Cloud integration options flow for Home Assistant."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Mapping
from datetime import datetime
from enum import StrEnum
from typing import Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import HomeAssistant
from homeassistant.helpers.instance_id import async_get as async_get_instance_id

from .api import (
    AuthResult,
    SubscriptionStatusResult,
    UserDict,
    authenticate,
    get_subscription_status,
    logout,
    signup,
)
from .const import (
    CONF_API_URI,
    DEFAULT_API_URI,
    SUBSCRIPTION_INVALID_STATES,
    SUBSCRIPTION_VALID_STATES,
    SubscriptionStatus,
)
from .exceptions import (
    EzloApiUnreachableError,
    EzloAuthError,
    EzloError,
)
from .frp_helpers import fetch_and_update_frp_config, start_frpc, stop_frpc
from .models import EzloConfigEntry, EzloRuntimeData

_LOGGER = logging.getLogger(__name__)

# 60-second cache for subscription status — the menu can be re-opened
# quickly and we don't want to hammer the backend.
_STATUS_CACHE_TTL = 60.0


class FlowState(StrEnum):
    """The single UI state an entry is in, shared by both flows."""

    LOGGED_OUT = "logged_out"
    SUBSCRIBED = "subscribed"
    EXPIRED = "expired"
    UNSUBSCRIBED = "unsubscribed"


def entry_state(data: Mapping[str, Any]) -> FlowState:
    """Classify a config entry's stored data into one UI state.

    Authentication and subscription are independent: a user can be logged in
    (credentials saved) yet unsubscribed. Both the options flow (cog) and the
    config flow (reconfigure) branch off this so they always agree.
    """
    if not data.get("is_logged_in") or not data.get("auth_token"):
        return FlowState.LOGGED_OUT
    status = data.get("subscription_status")
    if status in SUBSCRIPTION_VALID_STATES:
        return FlowState.SUBSCRIBED
    if status in SUBSCRIPTION_INVALID_STATES and status != SubscriptionStatus.NONE.value:
        return FlowState.EXPIRED
    return FlowState.UNSUBSCRIBED


def classify_login_error(error: str | None) -> tuple[str, str]:
    """Map a backend login-failure string to a (translation key, detail) tuple.

    ``POST /api/auth/login`` and ``/signup`` also enforce the binding between
    this Home Assistant instance and an account: a 409 whose message carries
    the ``device_already_bound`` code means the instance is linked to a
    different account. Without classification the UI would mislabel every
    failure as "Invalid username or password".
    """
    if not error:
        return "unknown", ""

    lower = error.lower()

    if "device_already_bound" in lower:
        return (
            "device_already_bound",
            "This Home Assistant installation is already linked to a"
            " different Ezlo Cloud HARC account.",
        )

    credential_markers = (
        "invalid credentials",
        "invalid username",
        "invalid password",
        "user not found",
        "unauthorized",
    )
    if any(marker in lower for marker in credential_markers):
        return "invalid_credentials", error

    return "unknown", error


def classify_signup_error(error: str | None) -> tuple[str, str]:
    """Map a backend signup-failure string to a (translation key, detail) tuple.

    Signup enforces the same instance binding as login, so a
    ``device_already_bound`` answer gets its dedicated message; anything else
    is a generic signup failure.
    """
    key, detail = classify_login_error(error)
    if key == "device_already_bound":
        return key, detail
    return "signup_failed", error or ""


async def release_backend_binding(
    hass: HomeAssistant, data: Mapping[str, Any], api_uri: str
) -> None:
    """Best-effort ``POST /api/auth/logout`` before clearing local credentials.

    Releases this HA instance's binding on the backend so another account can
    log in here afterwards. Skipped when there is no token to present.
    """
    token = data.get("auth_token")
    if not token:
        return
    if not await logout(hass, auth_token=str(token), api_uri=api_uri):
        _LOGGER.info(
            "Backend did not acknowledge logout; the instance binding may need "
            "to be released by support before another account can log in here"
        )


def compute_trial_days(trial_ends_at: str | None) -> int | None:
    """Compute remaining trial days from an ISO datetime string."""
    if not trial_ends_at:
        return None
    try:
        end_dt = datetime.fromisoformat(trial_ends_at.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    now = datetime.now(tz=end_dt.tzinfo)
    remaining = (end_dt - now).days
    return max(remaining, 0)


class EzloOptionsFlowHandler(config_entries.OptionsFlow):
    """Handles the options flow (the cog) for Ezlo HA Cloud.

    A single flat screen driven by ``entry_state``: logged-out shows login /
    create-account; subscribed shows connection details; unsubscribed/expired
    shows the subscribe/resubscribe link. Every logged-in screen offers Log out.
    """

    def __init__(self, config_entry: EzloConfigEntry) -> None:
        """Initialize options flow."""
        self._config_entry: EzloConfigEntry = config_entry

    # ── Helpers ──────────────────────────────────────────────────

    def _runtime(self) -> EzloRuntimeData | None:
        """Return the runtime data on the bound entry, if set up."""
        runtime: EzloRuntimeData | None = getattr(
            self._config_entry, "runtime_data", None
        )
        if isinstance(runtime, EzloRuntimeData):
            return runtime
        return None

    def _get_abort_placeholders(self) -> dict[str, str]:
        """Build description placeholders for abort messages."""
        cloud_url = self._get_cloud_url()
        sub_status = self._config_entry.data.get("subscription_status", "")
        trial_ends_at = self._config_entry.data.get("trial_ends_at")

        url_text = cloud_url if cloud_url else "Not yet available"
        trial_text = _trial_text_for_status(sub_status, trial_ends_at)

        return {"cloud_url": url_text, "trial_info": trial_text}

    def _get_cloud_url(self) -> str:
        """Build the cloud URL from frpc config data."""
        subdomain = self._config_entry.data.get("subdomain", "")
        server_name = self._config_entry.data.get("server_name", "")
        if subdomain and server_name:
            return f"https://{subdomain}.{server_name}"
        return ""

    def _get_api_uri(self) -> str:
        """Return the API URI for the current config entry."""
        api_uri = self._config_entry.data.get(CONF_API_URI) or DEFAULT_API_URI
        return str(api_uri)

    def _with_advanced(self, menu_options: dict[str, str]) -> dict[str, str]:
        """Append the advanced entry to a menu when advanced options are on."""
        if self.show_advanced_options:
            return {**menu_options, "advanced": "Advanced (API endpoint)"}
        return menu_options

    def _ensure_payment_poll(
        self,
        user_uuid: str,
        token: str,
        tunnel_token: str | None,
        user_info: dict[str, Any],
    ) -> None:
        """(Re)start the background poll that completes login once subscribed."""
        runtime = self._runtime()
        if runtime is not None and runtime.payment_poll_task is not None:
            runtime.payment_poll_task.cancel()
        task = self.hass.async_create_task(
            self._poll_payment_and_login(user_uuid, token, tunnel_token, user_info)
        )
        if runtime is not None:
            runtime.payment_poll_task = task

    # ── Main screen (state-driven, flat) ─────────────────────────

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        """Render the single state-appropriate screen."""
        data = self._config_entry.data
        state = entry_state(data)

        if state is FlowState.LOGGED_OUT:
            return self.async_show_menu(
                step_id="init",
                menu_options=self._with_advanced(
                    {"login": "Log in", "signup": "Create a new account"}
                ),
                description_placeholders={"body": "Log in or create an account."},
            )

        if state is FlowState.SUBSCRIBED:
            runtime = self._runtime()
            connected = runtime is not None and runtime.is_connected
            user_data = data.get("user", {}) or {}
            cloud_url = self._get_cloud_url() or "Not available"
            status_line = _trial_text_for_status(
                data.get("subscription_status", ""), data.get("trial_ends_at")
            )
            body = (
                f"**Status:** {'Connected' if connected else 'Disconnected'}\n\n"
                f"**Account:** {user_data.get('username', 'Unknown')}\n\n"
                f"**Remote URL:** [{cloud_url}]({cloud_url})"
            )
            if status_line:
                body += f"\n\n{status_line}"
            return self.async_show_menu(
                step_id="init",
                menu_options=self._with_advanced({"logout": "Log out"}),
                description_placeholders={"body": body},
            )

        # Partner access is admin-managed — the user cannot self-serve, so show the
        # contact-your-account-manager message with no subscribe link and no poll.
        sub_status = data.get("subscription_status")
        if sub_status == SubscriptionStatus.PARTNER_TRIAL_EXPIRED.value:
            return self.async_show_menu(
                step_id="init",
                menu_options=self._with_advanced({"logout": "Log out"}),
                description_placeholders={
                    "body": _trial_text_for_status(sub_status, data.get("trial_ends_at"))
                },
            )

        # UNSUBSCRIBED or EXPIRED (regular self-serve) — surface the subscribe/resubscribe link.
        user_data = data.get("user", {}) or {}
        user_uuid = user_data.get("uuid")
        url = ""
        if user_uuid:
            status = await self._get_cached_subscription_status(user_uuid)
            if status is not None:
                url = status.subscribe_url
            # Auto-complete login once the subscription lands.
            self._ensure_payment_poll(
                user_uuid,
                data.get("auth_token") or "",
                data.get("tunnel_token"),
                dict(user_data),
            )
        action = "Resubscribe" if state is FlowState.EXPIRED else "Subscribe"
        account_line = f"**Account:** {user_data.get('username', 'Unknown')}\n\n"
        if url:
            body = (
                f"{account_line}"
                f"You don't have an active subscription.\n\n"
                f"[{action} to Ezlo Cloud HARC]({url})\n\n"
                "This page updates automatically once your subscription is confirmed."
            )
        else:
            body = (
                f"{account_line}"
                "You don't have an active subscription, and the subscribe link "
                "could not be loaded right now. Please try again shortly."
            )
        return self.async_show_menu(
            step_id="init",
            menu_options=self._with_advanced({"logout": "Log out"}),
            description_placeholders={"body": body},
        )

    # ── Advanced ─────────────────────────────────────────────────

    async def async_step_advanced(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        """Override the Ezlo Cloud API endpoint for this entry."""
        if not self.show_advanced_options:
            return self.async_abort(reason="advanced_disabled")

        if user_input is not None:
            api_uri = (user_input.get(CONF_API_URI) or "").strip()
            new_data = dict(self._config_entry.data)
            if api_uri:
                new_data[CONF_API_URI] = api_uri
            else:
                new_data.pop(CONF_API_URI, None)
            self.hass.config_entries.async_update_entry(
                self._config_entry, data=new_data
            )
            return self.async_abort(reason="config_saved")

        current = self._get_api_uri()
        return self.async_show_form(
            step_id="advanced",
            data_schema=vol.Schema(
                {
                    vol.Optional(CONF_API_URI, default=current): str,
                }
            ),
            description_placeholders={
                "current_api_uri": current,
                "default_api_uri": DEFAULT_API_URI,
            },
        )

    # ── Logout ───────────────────────────────────────────────────

    async def async_step_logout(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        """Handle manual logout action."""
        await release_backend_binding(
            self.hass, self._config_entry.data, self._get_api_uri()
        )
        self.hass.config_entries.async_update_entry(
            self._config_entry, data=_logged_out_data(self._config_entry.data)
        )
        await stop_frpc(self.hass, self._config_entry)
        return self.async_abort(reason="logged_out")

    # ── Login ────────────────────────────────────────────────────

    async def async_step_login(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        """Handle login authentication form."""
        errors: dict[str, str] = {}
        login_error_detail = ""

        if user_input is not None:
            username = user_input["username"]
            password = user_input["password"]
            system_uuid = await async_get_instance_id(self.hass) or ""

            try:
                result = await authenticate(
                    self.hass,
                    username,
                    password,
                    system_uuid,
                    api_uri=self._get_api_uri(),
                )
            except EzloAuthError as err:
                error_key, login_error_detail = classify_login_error(str(err))
                errors["base"] = error_key
            except EzloApiUnreachableError as err:
                errors["base"] = "network_error"
                login_error_detail = str(err)
            except EzloError as err:
                errors["base"] = "unknown"
                login_error_detail = str(err)
            else:
                if result.payment_required:
                    self._persist_unsubscribed(result)
                    return await self.async_step_init()

                await self._handle_successful_login(result)
                return self.async_abort(
                    reason="login_successful",
                    description_placeholders=self._get_abort_placeholders(),
                )

        return self.async_show_form(
            step_id="login",
            data_schema=vol.Schema(
                {
                    vol.Required("username"): str,
                    vol.Required("password"): str,
                }
            ),
            errors=errors,
            description_placeholders={"error_detail": login_error_detail},
        )

    # ── Signup ───────────────────────────────────────────────────

    async def async_step_signup(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        """Handle account signup."""
        errors: dict[str, str] = {}
        signup_error_detail = ""

        if user_input is not None:
            username = user_input["username"]
            email = user_input["email"]
            password = user_input["password"]
            system_uuid = await async_get_instance_id(self.hass) or ""

            try:
                result = await signup(
                    self.hass,
                    username,
                    email,
                    password,
                    system_uuid,
                    api_uri=self._get_api_uri(),
                )
            except EzloAuthError as err:
                errors["base"], signup_error_detail = classify_signup_error(str(err))
            except EzloApiUnreachableError as err:
                errors["base"] = "network_error"
                signup_error_detail = str(err)
            except EzloError as err:
                errors["base"] = "signup_failed"
                signup_error_detail = str(err)
            else:
                if not result.payment_required:
                    await self._handle_successful_login(result)
                    return self.async_abort(
                        reason="signup_trial_started",
                        description_placeholders=self._get_abort_placeholders(),
                    )

                self._persist_unsubscribed(result)
                return await self.async_step_init()

        return self.async_show_form(
            step_id="signup",
            data_schema=vol.Schema(
                {
                    vol.Required("username"): str,
                    vol.Required("email"): str,
                    vol.Required("password"): str,
                }
            ),
            errors=errors,
            description_placeholders={"error_detail": signup_error_detail},
        )

    # ── Shared entry-data writers ────────────────────────────────

    def _persist_unsubscribed(self, result: AuthResult) -> None:
        """Persist an authenticated-but-unsubscribed login on the entry.

        is_logged_in=True (credentials saved) with payment_required=True so the
        state screen shows the subscribe link, not the login menu.
        """
        new_data = dict(self._config_entry.data)
        new_data.update(
            {
                "auth_token": result.token,
                "tunnel_token": result.tunnel_token,
                "user": dict(result.user),
                "is_logged_in": True,
                "subscription_status": result.subscription_status,
                "trial_ends_at": result.trial_ends_at,
                "payment_required": True,
            }
        )
        self.hass.config_entries.async_update_entry(self._config_entry, data=new_data)

    async def _handle_successful_login(self, result: AuthResult) -> None:
        """Shared logic to handle a subscribed login/signup — starts the tunnel."""
        new_data = dict(self._config_entry.data)
        new_data.update(
            {
                "auth_token": result.token,
                "tunnel_token": result.tunnel_token,
                "user": dict(result.user),
                "is_logged_in": True,
                "subscription_status": result.subscription_status,
                "trial_ends_at": result.trial_ends_at,
                "payment_required": False,
            }
        )
        self.hass.config_entries.async_update_entry(self._config_entry, data=new_data)

        try:
            frp_info = await fetch_and_update_frp_config(
                hass=self.hass,
                uuid=result.user.get("uuid", ""),
                token=result.token,
                api_uri=self._get_api_uri(),
            )
        except EzloError as err:
            _LOGGER.error("Failed to fetch the server details: %s", err)
        except (OSError, ValueError, RuntimeError) as err:
            _LOGGER.error("Failed to fetch the server details: %s", err)
        else:
            updated_data = dict(self._config_entry.data)
            updated_data["server_name"] = frp_info.get("server_name", "")
            updated_data["subdomain"] = frp_info.get("subdomain", "")
            self.hass.config_entries.async_update_entry(
                self._config_entry, data=updated_data
            )
            await start_frpc(hass=self.hass, config_entry=self._config_entry)

        self.hass.async_create_task(
            self.hass.config_entries.async_reload(self._config_entry.entry_id)
        )

    # ── Payment polling ──────────────────────────────────────────

    async def _poll_payment_and_login(
        self,
        user_uuid: str,
        token: str,
        tunnel_token: str | None,
        user_info: dict[str, Any],
    ) -> None:
        """Poll subscription status until valid, then complete login."""
        timeout = 15 * 60
        interval = 5
        attempts = timeout // interval
        for _ in range(attempts):
            try:
                await asyncio.sleep(interval)
            except asyncio.CancelledError:
                _LOGGER.debug("payment polling cancelled")
                return

            try:
                status = await get_subscription_status(
                    self.hass, user_uuid, auth_token=token, api_uri=self._get_api_uri()
                )
            except EzloAuthError as err:
                # The token itself was rejected; polling again will not change that.
                _LOGGER.warning(
                    "Subscription poll stopped: token rejected (%s). Please log in again",
                    err,
                )
                return
            except EzloError:
                continue

            if status.status in SUBSCRIPTION_VALID_STATES:
                _LOGGER.info("Subscription is %s. Completing login", status.status)
                user = UserDict(
                    uuid=user_info.get("uuid", ""),
                    username=user_info.get("username", ""),
                    email=user_info.get("email", ""),
                    ezlo_id=user_info.get("ezlo_id", ""),
                )
                synthetic = AuthResult(
                    token=token,
                    tunnel_token=tunnel_token,
                    user=user,
                    subscription_status=status.status,
                    is_trial=status.is_trial,
                    payment_required=False,
                    trial_ends_at=status.trial_ends_at or None,
                    checkout_url=None,
                )
                await self._handle_successful_login(synthetic)
                return

        _LOGGER.warning("Polling timeout: subscription did not activate")

    async def _get_cached_subscription_status(
        self, user_uuid: str
    ) -> SubscriptionStatusResult | None:
        """Return cached subscription status, refreshing if past TTL."""
        runtime = self._runtime()
        now = time.monotonic()
        if runtime is not None and runtime.subscription_cache is not None:
            ts, cached = runtime.subscription_cache
            if now - ts < _STATUS_CACHE_TTL:
                return SubscriptionStatusResult(
                    status=str(cached.get("status", "unknown")),
                    is_active=bool(cached.get("is_active", False)),
                    is_trial=bool(cached.get("is_trial", False)),
                    trial_ends_at=str(cached.get("trial_ends_at", "")),
                    subscribe_url=str(cached.get("subscribe_url", "")),
                )

        token = self._config_entry.data.get("auth_token")
        if not token:
            return None
        try:
            result = await get_subscription_status(
                self.hass, user_uuid, auth_token=token, api_uri=self._get_api_uri()
            )
        except EzloError as err:
            _LOGGER.debug("subscription status fetch failed: %s", err)
            return None

        if runtime is not None:
            runtime.subscription_cache = (
                now,
                {
                    "status": result.status,
                    "is_active": result.is_active,
                    "is_trial": result.is_trial,
                    "trial_ends_at": result.trial_ends_at,
                    "subscribe_url": result.subscribe_url,
                },
            )
        return result


# ── Module-private helpers ────────────────────────────────────────


def _logged_out_data(data: Mapping[str, Any]) -> dict[str, Any]:
    """Return a copy of entry data with all auth/subscription fields cleared."""
    cleared = dict(data)
    cleared.update(
        {
            "is_logged_in": False,
            "auth_token": None,
            "tunnel_token": None,
            "user": {},
            "subscription_status": None,
            "trial_ends_at": None,
            "payment_required": False,
        }
    )
    return cleared


def _trial_text_for_status(sub_status: str | None, trial_ends_at: str | None) -> str:
    """Render the contextual trial/subscription text for a status."""
    if sub_status == SubscriptionStatus.FEATURE_HARC.value:
        return "Your Ezlo subscription is active."
    if sub_status == SubscriptionStatus.TRIALING.value:
        days = compute_trial_days(trial_ends_at)
        if days is not None:
            return (
                f"Free trial: {days} day{'s' if days != 1 else ''} remaining. "
                "Your card will be charged automatically when the trial ends."
            )
        return (
            "You are on a free trial. "
            "Your card will be charged automatically when the trial ends."
        )
    if sub_status == SubscriptionStatus.INTERNAL.value:
        return "Internal user — unlimited access. No subscription required."
    if sub_status == SubscriptionStatus.PARTNER_TRIAL.value:
        days = compute_trial_days(trial_ends_at)
        if days is not None:
            return (
                f"Partner trial: {days} day{'s' if days != 1 else ''} remaining. "
                "Contact your account manager before it ends."
            )
        return "Partner trial active. Contact your account manager before it ends."
    if sub_status == SubscriptionStatus.PARTNER_TRIAL_EXPIRED.value:
        return (
            "Your partner trial has expired. "
            "Contact your account manager to restore access."
        )
    if sub_status == SubscriptionStatus.ACTIVE.value:
        return "Your subscription is active."
    if sub_status == SubscriptionStatus.PAST_DUE.value:
        return (
            "Your last payment failed. "
            "Update your payment method to restore remote access."
        )
    if sub_status == SubscriptionStatus.CANCELED.value:
        return "Your subscription was canceled. Resubscribe to restore remote access."
    if sub_status == SubscriptionStatus.NONE.value:
        return (
            "You don't have an active subscription. "
            "Subscribe to enable remote access."
        )
    return ""
