"""H2 switch rules: a sidebar panel for rule programs of H2 switches (h2-zigbee firmware).

The panel compiles C to the firmware's eBPF image in the browser and talks to the
switches through ZHA's own websocket command and action, so this integration only serves
the panel's files and keeps the sources (see store.py).
"""

from __future__ import annotations

from pathlib import Path

import voluptuous as vol

from homeassistant.components import panel_custom, websocket_api
from homeassistant.components.http import StaticPathConfig
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.loader import async_get_integration

from . import store
from .const import DOMAIN, PANEL_ELEMENT, PANEL_URL_PATH, SOURCE_DIR, STATIC_URL

FRONTEND = Path(__file__).parent / "frontend"


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    data = hass.data.setdefault(DOMAIN, {})
    if not data.get("static"):
        # Registered once per run of Home Assistant: paths and commands cannot be removed.
        await hass.http.async_register_static_paths(
            [StaticPathConfig(STATIC_URL, str(FRONTEND), cache_headers=False)]
        )
        websocket_api.async_register_command(hass, ws_source_get)
        websocket_api.async_register_command(hass, ws_source_save)
        websocket_api.async_register_command(hass, ws_source_list)
        data["static"] = True

    integration = await async_get_integration(hass, DOMAIN)
    await panel_custom.async_register_panel(
        hass,
        webcomponent_name=PANEL_ELEMENT,
        frontend_url_path=PANEL_URL_PATH,
        module_url=f"{STATIC_URL}/panel.js?v={integration.version}",
        sidebar_title="H2 rules",
        sidebar_icon="mdi:light-switch",
        require_admin=True,
        embed_iframe=True,
        config={"static": STATIC_URL, "version": str(integration.version)},
    )
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    from homeassistant.components import frontend

    frontend.async_remove_panel(hass, PANEL_URL_PATH)
    return True


def _dir(hass: HomeAssistant) -> Path:
    return Path(hass.config.path(SOURCE_DIR))


@websocket_api.websocket_command({vol.Required("type"): "h2_rules/source/get", vol.Required("ieee"): str})
@websocket_api.require_admin
@websocket_api.async_response
async def ws_source_get(hass: HomeAssistant, connection, msg) -> None:
    try:
        result = await hass.async_add_executor_job(store.load, _dir(hass), msg["ieee"])
    except ValueError as err:
        connection.send_error(msg["id"], "invalid", str(err))
        return
    connection.send_result(msg["id"], result)


@websocket_api.websocket_command(
    {
        vol.Required("type"): "h2_rules/source/save",
        vol.Required("ieee"): str,
        vol.Optional("source"): vol.Any(str, None),
        vol.Optional("image"): vol.Any(str, None),
        vol.Optional("meta", default=dict): dict,
    }
)
@websocket_api.require_admin
@websocket_api.async_response
async def ws_source_save(hass: HomeAssistant, connection, msg) -> None:
    try:
        meta = await hass.async_add_executor_job(
            store.save, _dir(hass), msg["ieee"], msg.get("source"), msg.get("image"), msg["meta"]
        )
    except (ValueError, OSError) as err:
        connection.send_error(msg["id"], "invalid", str(err))
        return
    connection.send_result(msg["id"], {"meta": meta})


@websocket_api.websocket_command({vol.Required("type"): "h2_rules/source/list"})
@websocket_api.require_admin
@websocket_api.async_response
async def ws_source_list(hass: HomeAssistant, connection, msg) -> None:
    result = await hass.async_add_executor_job(store.listing, _dir(hass))
    connection.send_result(msg["id"], {"sources": result})
