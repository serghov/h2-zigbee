"""ZHA quirk for the h2-zigbee custom firmware on the Aqara H2 EU dimmer and switches.

The firmware reports manufacturer "h2-zigbee" and the stock model (dimmer
"lumi.switch.agl011", switch "lumi.switch.agl009" / "lumi.switch.agl010"),
so ZHA's own quirk for the stock firmware (manufacturer "Aqara") does not apply.
Copy this file into the directory named by `zha: custom_quirks_path:`.
"""

from zigpy import types as t
from zigpy.profiles import zha
from zigpy.zcl.foundation import BaseAttributeDefs, ZCLAttributeDef

from zhaquirks.builder import QuirkBuilder
from zhaquirks.xiaomi import XiaomiAqaraE1Cluster


class HexBytes(t.LVBytes):
    """Octet string that can also be given as a hex string.

    Home Assistant's `zha.set_zigbee_cluster_attribute` action only passes numbers and
    strings, so rule program chunks are written as hex text.
    """

    def __new__(cls, value=b""):
        if isinstance(value, str):
            value = bytes.fromhex(value)
        return super().__new__(cls, value)


def _attr(attr_id, attr_type, access="rw"):
    return ZCLAttributeDef(id=attr_id, type=attr_type, access=access, is_manufacturer_specific=True)


class H2Cluster(XiaomiAqaraE1Cluster):
    """Aqara manufacturer cluster (0xFCC0) with the h2-zigbee additions."""

    class AttributeDefs(BaseAttributeDefs):
        # Stock attributes the firmware implements
        flip_indicator_light = _attr(0x00F0, t.uint8_t)
        operation_mode = _attr(0x0200, t.uint8_t)
        led_indicator = _attr(0x0203, t.uint8_t)
        # Rule engine (common/h2_rules.h)
        rules_control = _attr(0xFFC0, t.uint32_t)
        rules_data = _attr(0xFFC1, HexBytes, "w")
        rules_info = _attr(0xFFC2, t.uint32_t, "r")
        rules_fault = _attr(0xFFC3, t.uint32_t, "r")
        # LED ownership bitmask (common/h2_led_ep.h)
        led_manual = _attr(0xFFD0, t.uint32_t)
        # Bench builds only (common/h2_tap.h)
        tap_mode = _attr(0xFFF1, t.uint8_t)
        tap_pin = _attr(0xFFF5, t.uint32_t, "w")
        # Scene slots (common/h2_scenes.h)
        scene_slot_0 = _attr(0xFFE0, t.uint32_t)
        scene_slot_1 = _attr(0xFFE1, t.uint32_t)
        scene_slot_2 = _attr(0xFFE2, t.uint32_t)
        scene_slot_3 = _attr(0xFFE3, t.uint32_t)
        scene_slot_4 = _attr(0xFFE4, t.uint32_t)
        scene_slot_5 = _attr(0xFFE5, t.uint32_t)
        scene_slot_6 = _attr(0xFFE6, t.uint32_t)
        scene_slot_7 = _attr(0xFFE7, t.uint32_t)


(
    # Dimmer
    QuirkBuilder("h2-zigbee", "lumi.switch.agl011")
    .replaces_endpoint(1, device_type=zha.DeviceType.DIMMABLE_LIGHT)
    .replaces(H2Cluster)
    .add_to_registry()
)

(
    # Switch, one gang (2 buttons) and two gangs (4 buttons). Not yet tried on hardware.
    QuirkBuilder("h2-zigbee", "lumi.switch.agl009")
    .applies_to("h2-zigbee", "lumi.switch.agl010")
    .replaces(H2Cluster)
    .add_to_registry()
)
