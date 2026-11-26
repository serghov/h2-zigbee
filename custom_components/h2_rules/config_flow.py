"""Config flow: one instance, nothing to configure."""

from homeassistant.config_entries import ConfigFlow

from .const import DOMAIN


class H2RulesConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input=None):
        if user_input is not None:
            return self.async_create_entry(title="H2 switch rules", data={})
        return self.async_show_form(step_id="user")
