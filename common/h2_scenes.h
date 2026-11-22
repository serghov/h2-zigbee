#ifndef H2_SCENES_H
#define H2_SCENES_H

// Direct scene recall: a local action (knob press, button press) sends a Zigbee Scenes
// "Recall Scene" command straight to a group, with no hub in the path.
//
// Each slot holds a group ID and a scene ID. Slots are configured over Zigbee with
// manufacturer-specific attributes on the Opple cluster (0xFCC0, endpoint 1, manufacturer
// code 0x115F), one uint32 per slot:
//
//   attribute  H2_SCENES_ATTR_BASE + slot
//   value      bits 0-15 group ID, bits 16-23 scene ID, bit 24 enabled
//
// The lights must be members of the group and have the scene stored. The plate itself
// does not need to be in the group, and no binding is needed.
//
// Which action uses which slot is up to the variant. The dimmer uses slots 0 and 1 for a
// knob press: slot 0 alone recalls that scene on every press; with slot 1 enabled as
// well, presses alternate between the two.

#include <stdint.h>
#include <stdbool.h>

#define H2_SCENES_SLOTS       8
#define H2_SCENES_ATTR_BASE   0xFFE0     // 0xFFE0 .. 0xFFE7

void h2_scenes_init(void);

// True if the slot is configured and enabled.
bool h2_scenes_enabled(uint8_t slot);

// Recall the slot's scene from the given source endpoint. Returns false if the slot is
// not enabled or the device is not on a network.
bool h2_scenes_recall(uint8_t slot, uint8_t source_endpoint);

// Attribute access for the Opple cluster handler. Both return false if attr_id is not a
// scene-slot attribute.
bool h2_scenes_attr_get(uint16_t attr_id, uint32_t *value);
bool h2_scenes_attr_set(uint16_t attr_id, uint32_t value);

#endif // H2_SCENES_H
