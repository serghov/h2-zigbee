#ifndef H2_LED_EP_H
#define H2_LED_EP_H

// LEDs as standard Zigbee lights.
//
// Each indicator LED has its own endpoint that presents as an HA Color Dimmable Light:
// On/Off, Level Control and Color Control (hue and saturation). A hub discovers it as an
// ordinary light. Endpoint H2_LED_EP_FIRST + n is LED n, in the order gang 0 up, gang 0
// down, gang 1 up, gang 1 down; a variant only has the endpoints for LEDs it has.
//
// The LEDs are red/blue only, so hue is mapped onto red/blue mixes: red and blue are
// exact, everything else becomes the nearest mix. Lower saturation moves towards both
// channels on. Level scales the result.
//
// Ownership: any command to an LED endpoint makes that LED "manual" (it holds what was
// set). Manufacturer attribute H2_LED_EP_ATTR_MANUAL on the Opple cluster is a bitmask of
// manual LEDs; clearing a bit hands that LED back to the indicator logic.

#include <stdint.h>
#include <stdbool.h>
#include "app/framework/include/af.h"

#define H2_LED_EP_FIRST         21
#define H2_LED_EP_ATTR_MANUAL   0xFFD0     // uint32 bitmask, bit n = LED n is manual

// Persistence: what a manual LED was set to (on/off, level, hue, saturation) is a setting,
// not transient state. It is saved to NVM3 a couple of seconds after the last change and
// restored after a restart or power loss. An automatic LED stores only that it is
// automatic.
//
// Call once from sl_zigbee_af_main_init_cb(); the restore itself runs shortly after boot,
// once the framework's attributes exist.
void h2_led_ep_init(void);

// Number of LED endpoints this variant has.
uint8_t h2_led_ep_count(void);

// Handle a cluster command addressed to an LED endpoint. Returns true if consumed
// (a default response has been sent). Call from sl_zigbee_af_pre_command_received_cb().
bool h2_led_ep_command(sl_zigbee_af_cluster_command_t *cmd);

// Call from sl_zigbee_af_post_attribute_change_cb() for every server attribute change.
void h2_led_ep_attribute_changed(uint8_t endpoint, uint16_t cluster_id);

// Set an LED directly by channel (0-255 each), for local logic such as rules. Makes the
// LED manual and updates the endpoint's attributes to match as far as they can.
void h2_led_ep_set_channels(uint8_t led, uint8_t red, uint8_t blue);

// Hand an LED back to the indicator logic.
void h2_led_ep_release(uint8_t led);

// Attribute access for the Opple cluster handler; false if attr_id is not ours.
bool h2_led_ep_attr_get(uint16_t attr_id, uint32_t *value);
bool h2_led_ep_attr_set(uint16_t attr_id, uint32_t value);

#endif // H2_LED_EP_H
