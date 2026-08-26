"""Config flow for Ezlo HA Cloud."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.config_entries import ConfigFlowResult
from homeassistant.core import callback
from homeassistant.helpers.instance_id import async_get as async_get_instance_id

from .api import AuthResult, authenticate, get_subscription_status, signup
from .const import CONF_API_URI, DEFAULT_API_URI, DOMAIN, SubscriptionStatus
from .exceptions import (
    EzloApiUnreachableError,
    EzloAuthError,
    EzloError,
)
from .models import EzloConfigData, EzloConfigEntry, EzloUserData
from .options_flow import (
    EzloOptionsFlowHandler,
    FlowState,
    classify_login_error,
    entry_state,
)

_LOGGER = logging.getLogger(__name__)


def build_entry_data(result: AuthResult) -> EzloConfigData:
    """Shape an AuthResult into the dict stored on the config entry.

    ``is_logged_in`` reflects authentication only — it is True whenever we hold a
    token, independent of subscription state. An authenticated-but-unsubscribed
    user is logged in (credentials saved, options flow shows the subscription
    menu); ``payment_required`` / ``subscription_status`` separately gate whether
    the tunnel starts. Conflating the two previously made unsubscribed logins look
    like auth failures.
    """
    return EzloConfigData(
        auth_token=result.token,
        tunnel_token=result.tunnel_token,
        user=EzloUserData(
            uuid=result.user.get("uuid", ""),
            username=result.user.get("username", ""),
            email=result.user.get("email", ""),
            ezlo_id=result.user.get("ezlo_id", ""),
        ),
        is_logged_in=bool(result.token),
        subscription_status=result.subscription_status,
        trial_ends_at=result.trial_ends_at,
        payment_required=result.payment_required,
    )


class EzloHACloudConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Config flow for Ezlo HA Cloud."""

    VERSION = 1
    MINOR_VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Initial step — show Log in / Create account menu."""
        await self.async_set_unique_id(DOMAIN, raise_on_progress=False)
        self._abort_if_unique_id_configured()
        return self.async_show_menu(
            step_id="user",
            menu_options={
                "login": "Log in",
                "signup": "Create a new account",
            },
        )

    async def async_step_login(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Collect credentials, authenticate, and create the config entry."""
        errors: dict[str, str] = {}
        login_error_detail = ""

        if user_input is not None:
            username = user_input["username"]
            password = user_input["password"]
            system_uuid = await async_get_instance_id(self.hass) or ""
            if not system_uuid:
                _LOGGER.warning("Home Assistant system_uuid missing!")

            try:
                result = await authenticate(self.hass, username, password, system_uuid)
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
                return self.async_create_entry(
                    title="Ezlo Cloud HARC",
                    data=dict(build_entry_data(result)),
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

    async def async_step_signup(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Create a new Ezlo Cloud account and create the config entry.

        When the backend says payment is required, the entry is still
        created (with `payment_required=True`) so the user can complete
        the central Ezlo subscription via the options flow's resubscribe path.
        """
        errors: dict[str, str] = {}
        signup_error_detail = ""

        if user_input is not None:
            username = user_input["username"]
            email = user_input["email"]
            password = user_input["password"]
            system_uuid = await async_get_instance_id(self.hass) or ""
            if not system_uuid:
                _LOGGER.warning("Home Assistant system_uuid missing!")

            try:
                result = await signup(
                    self.hass, username, email, password, system_uuid
                )
            except EzloAuthError as err:
                errors["base"] = "signup_failed"
                signup_error_detail = str(err)
            except EzloApiUnreachableError as err:
                errors["base"] = "network_error"
                signup_error_detail = str(err)
            except EzloError as err:
                errors["base"] = "signup_failed"
                signup_error_detail = str(err)
            else:
                return self.async_create_entry(
                    title="Ezlo Cloud HARC",
                    data=dict(build_entry_data(result)),
                )

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

    # ── Reauthentication ────────────────────────────────────────

    async def async_step_reauth(
        self, entry_data: Mapping[str, Any]
    ) -> ConfigFlowResult:
        """Handle a re-auth trigger from async_setup_entry."""
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Prompt for credentials and update the existing entry."""
        errors: dict[str, str] = {}
        login_error_detail = ""

        if user_input is not None:
            username = user_input["username"]
            password = user_input["password"]
            system_uuid = await async_get_instance_id(self.hass) or ""
            try:
                result = await authenticate(self.hass, username, password, system_uuid)
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
                entry = self._get_reauth_entry()
                return self.async_update_reload_and_abort(
                    entry, data_updates=dict(build_entry_data(result))
                )

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema(
                {
                    vol.Required("username"): str,
                    vol.Required("password"): str,
                }
            ),
            errors=errors,
            description_placeholders={"error_detail": login_error_detail},
        )

    # ── Reconfigure = state-driven action dispatcher ────────────

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Show the single action relevant to the entry's current state."""
        entry = self._get_reconfigure_entry()
        state = entry_state(entry.data)

        if state is FlowState.LOGGED_OUT:
            return self.async_show_menu(
                step_id="reconfigure",
                menu_options={
                    "reconfigure_login": "Log in",
                    "reconfigure_signup": "Create a new account",
                },
                description_placeholders={"body": "You are logged out."},
            )

        if state is FlowState.SUBSCRIBED:
            return self.async_show_menu(
                step_id="reconfigure",
                menu_options={"reconfigure_logout": "Log out"},
                description_placeholders={
                    "body": "You're logged in and subscribed."
                },
            )

        # Partner access is admin-managed — no self-serve subscribe link.
        if entry.data.get("subscription_status") == SubscriptionStatus.PARTNER_TRIAL_EXPIRED.value:
            return self.async_show_menu(
                step_id="reconfigure",
                menu_options={"reconfigure_logout": "Log out"},
                description_placeholders={
                    "body": "Your partner access has expired. Contact your account "
                    "manager to restore access."
                },
            )

        # UNSUBSCRIBED or EXPIRED (regular self-serve) — show the subscribe/resubscribe link.
        action = "Resubscribe" if state is FlowState.EXPIRED else "Subscribe"
        username = (entry.data.get("user") or {}).get("username", "Unknown")
        account_line = f"**Account:** {username}\n\n"
        url = await self._reconfigure_subscribe_url(entry)
        if url:
            body = (
                f"{account_line}"
                "You don't have an active subscription.\n\n"
                f"[{action} to Ezlo Cloud HARC]({url})"
            )
        else:
            body = (
                f"{account_line}"
                "You don't have an active subscription, and the subscribe link "
                "could not be loaded right now. Please try again shortly."
            )
        return self.async_show_menu(
            step_id="reconfigure",
            menu_options={"reconfigure_logout": "Log out"},
            description_placeholders={"body": body},
        )

    async def _reconfigure_subscribe_url(self, entry: EzloConfigEntry) -> str:
        """Fetch the central subscribe URL for the reconfigure entry, or ''."""
        user = entry.data.get("user") or {}
        uuid = user.get("uuid")
        token = entry.data.get("auth_token")
        if not uuid or not token:
            return ""
        api_uri = entry.data.get(CONF_API_URI) or DEFAULT_API_URI
        try:
            status = await get_subscription_status(
                self.hass, uuid, auth_token=token, api_uri=api_uri
            )
        except EzloError:
            return ""
        return status.subscribe_url

    async def async_step_reconfigure_login(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Log in and update the existing entry in place."""
        errors: dict[str, str] = {}
        login_error_detail = ""

        if user_input is not None:
            entry = self._get_reconfigure_entry()
            api_uri = entry.data.get(CONF_API_URI) or DEFAULT_API_URI
            system_uuid = await async_get_instance_id(self.hass) or ""
            try:
                result = await authenticate(
                    self.hass,
                    user_input["username"],
                    user_input["password"],
                    system_uuid,
                    api_uri=api_uri,
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
                return self.async_update_reload_and_abort(
                    entry, data_updates=dict(build_entry_data(result))
                )

        return self.async_show_form(
            step_id="reconfigure_login",
            data_schema=vol.Schema(
                {
                    vol.Required("username"): str,
                    vol.Required("password"): str,
                }
            ),
            errors=errors,
            description_placeholders={"error_detail": login_error_detail},
        )

    async def async_step_reconfigure_signup(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Create an account and update the existing entry in place."""
        errors: dict[str, str] = {}
        signup_error_detail = ""

        if user_input is not None:
            entry = self._get_reconfigure_entry()
            api_uri = entry.data.get(CONF_API_URI) or DEFAULT_API_URI
            system_uuid = await async_get_instance_id(self.hass) or ""
            try:
                result = await signup(
                    self.hass,
                    user_input["username"],
                    user_input["email"],
                    user_input["password"],
                    system_uuid,
                    api_uri=api_uri,
                )
            except EzloAuthError as err:
                errors["base"] = "signup_failed"
                signup_error_detail = str(err)
            except EzloApiUnreachableError as err:
                errors["base"] = "network_error"
                signup_error_detail = str(err)
            except EzloError as err:
                errors["base"] = "signup_failed"
                signup_error_detail = str(err)
            else:
                return self.async_update_reload_and_abort(
                    entry, data_updates=dict(build_entry_data(result))
                )

        return self.async_show_form(
            step_id="reconfigure_signup",
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

    async def async_step_reconfigure_logout(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Clear credentials and reload (the entry idles logged-out)."""
        entry = self._get_reconfigure_entry()
        return self.async_update_reload_and_abort(
            entry,
            data_updates={
                "is_logged_in": False,
                "auth_token": None,
                "tunnel_token": None,
                "user": {},
                "subscription_status": None,
                "trial_ends_at": None,
                "payment_required": False,
            },
            reason="logged_out",
        )

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: EzloConfigEntry,
    ) -> EzloOptionsFlowHandler:
        """Enable the 'Configure' and 'Login' buttons in the UI."""
        return EzloOptionsFlowHandler(config_entry)
