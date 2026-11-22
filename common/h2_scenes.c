#include "app/framework/include/af.h"
#include "nvm3_default.h"

#include "h2_scenes.h"

#define NVM3_KEY_SCENES   0x0220     // one object holding all slots
#define SLOT_ENABLED      (1UL << 24)

static uint32_t slots[H2_SCENES_SLOTS];

void h2_scenes_init(void)
{
  if (nvm3_readData(nvm3_defaultHandle, NVM3_KEY_SCENES, slots, sizeof(slots)) != ECODE_NVM3_OK) {
    memset(slots, 0, sizeof(slots));
  }
}

bool h2_scenes_enabled(uint8_t slot)
{
  return slot < H2_SCENES_SLOTS && (slots[slot] & SLOT_ENABLED) != 0;
}

bool h2_scenes_recall(uint8_t slot, uint8_t source_endpoint)
{
  if (!h2_scenes_enabled(slot)
      || sl_zigbee_af_network_state() != SL_ZIGBEE_JOINED_NETWORK) {
    return false;
  }
  uint16_t group = (uint16_t)(slots[slot] & 0xFFFF);
  uint8_t scene = (uint8_t)((slots[slot] >> 16) & 0xFF);

  // Recall Scene without the optional transition-time field, which older lights reject.
  sl_zigbee_af_fill_external_buffer((ZCL_CLUSTER_SPECIFIC_COMMAND
                                     | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER
                                     | ZCL_DISABLE_DEFAULT_RESPONSE_MASK),
                                    ZCL_SCENES_CLUSTER_ID,
                                    ZCL_RECALL_SCENE_COMMAND_ID,
                                    "vu",
                                    group, scene);
  sl_zigbee_af_set_command_endpoints(source_endpoint, 0xFF);
  sl_status_t status = sl_zigbee_af_send_command_multicast(group, SL_ZIGBEE_NULL_NODE_ID, 0);
  sl_zigbee_app_debug_println("Scene recall: slot %d group 0x%04X scene %d -> 0x%02X",
                               slot, group, scene, status);
  return status == SL_STATUS_OK;
}

bool h2_scenes_attr_get(uint16_t attr_id, uint32_t *value)
{
  if (attr_id < H2_SCENES_ATTR_BASE || attr_id >= H2_SCENES_ATTR_BASE + H2_SCENES_SLOTS) {
    return false;
  }
  *value = slots[attr_id - H2_SCENES_ATTR_BASE];
  return true;
}

bool h2_scenes_attr_set(uint16_t attr_id, uint32_t value)
{
  if (attr_id < H2_SCENES_ATTR_BASE || attr_id >= H2_SCENES_ATTR_BASE + H2_SCENES_SLOTS) {
    return false;
  }
  slots[attr_id - H2_SCENES_ATTR_BASE] = value & (SLOT_ENABLED | 0x00FFFFFFUL);
  nvm3_writeData(nvm3_defaultHandle, NVM3_KEY_SCENES, slots, sizeof(slots));
  return true;
}
