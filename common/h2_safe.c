#include "app/framework/include/af.h"
#include "nvm3_default.h"
#include "em_gpio.h"
#include "network-steering.h"

#include "h2_safe.h"
#include "h2_build.h"
#include "h2_led_config.h"
#include "h2_opple.h"

#define NVM3_KEY_SAFE      0x0210   // Opple uses 0x0100..0x011F, power 0x0200, dimmer 0x0201
#define SAFE_TICK_MS       250

typedef struct {
  uint32_t version;
  uint8_t  fails;
  uint16_t resets[H2_SAFE_RESET_HISTORY];   // newest first
} safe_record_t;

static safe_record_t record;
static bool safe_mode;
static uint32_t ticks;
static sl_zigbee_af_event_t safe_tick_event;

static void save_record(void)
{
  nvm3_writeData(nvm3_defaultHandle, NVM3_KEY_SAFE, &record, sizeof(record));
}

bool h2_safe_boot(uint32_t firmware_version)
{
  safe_record_t stored;
  if (nvm3_readData(nvm3_defaultHandle, NVM3_KEY_SAFE, &stored, sizeof(stored)) != ECODE_NVM3_OK
      || stored.version != firmware_version) {
    // New firmware version (or no record): start counting again, keep no history.
    memset(&stored, 0, sizeof(stored));
    stored.version = firmware_version;
  }
  record = stored;
  for (int i = H2_SAFE_RESET_HISTORY - 1; i > 0; i--) {
    record.resets[i] = record.resets[i - 1];
  }
  record.resets[0] = halGetExtendedResetInfo();
  if (record.fails < 255) {
    record.fails++;
  }
  safe_mode = record.fails > H2_SAFE_FAIL_LIMIT;
  save_record();
  return safe_mode;
}

bool h2_safe_mode_active(void)
{
  return safe_mode;
}

uint8_t h2_safe_fail_count(void)
{
  return record.fails;
}

static void safe_tick_handler(sl_zigbee_af_event_t *event)
{
  ticks++;
  uint32_t seconds = ticks * SAFE_TICK_MS / 1000;

  if (!safe_mode) {
    if (seconds >= H2_SAFE_HEALTHY_S) {
      record.fails = 0;          // this boot counts as healthy
      save_record();
      return;                    // stop ticking
    }
  } else {
    GPIO_PinOutToggle(H2_LED_UP_R_PORT, H2_LED_UP_R_PIN);
#if H2_BENCH
    // Without a network there is no OTA and no way out except a wired flash, so keep
    // trying to join any open network. Normal mode leaves joining to the user.
    if (ticks % (H2_SAFE_JOIN_RETRY_S * 1000 / SAFE_TICK_MS) == (2000 / SAFE_TICK_MS)
        && sl_zigbee_af_network_state() == SL_ZIGBEE_NO_NETWORK) {
      sl_zigbee_af_network_steering_start();
    }
#endif
    if (seconds >= (uint32_t)H2_SAFE_EXIT_MIN * 60) {
      record.fails = 0;          // give normal mode another try
      save_record();
      halReboot();
    }
  }
  sl_zigbee_af_event_set_delay_ms(event, SAFE_TICK_MS);
}

void h2_safe_start(void)
{
  if (safe_mode) {
    GPIO_PinModeSet(H2_LED_UP_R_PORT, H2_LED_UP_R_PIN, gpioModePushPull, 0);
  }
  sl_zigbee_af_event_init(&safe_tick_event, safe_tick_handler);
  sl_zigbee_af_event_set_delay_ms(&safe_tick_event, SAFE_TICK_MS);
}

// ---------------------------------------------------------------------------
// Boot diagnostics over Zigbee. Self-contained on purpose: it must work in safe mode,
// when none of the normal Opple handling runs.
// ---------------------------------------------------------------------------

bool h2_safe_handle_diag_read(uint8_t endpoint, uint16_t source_node,
                              const uint8_t *msg, uint16_t msg_len)
{
  // Manufacturer-specific global Read Attributes for exactly this one attribute:
  // [fc][mfg lo][mfg hi][seq][cmd=0x00][attr lo][attr hi]
  if (msg_len != 7) return false;
  if ((msg[0] & 0x07) != 0x04) return false;                 // global, mfg-specific
  if ((msg[1] | ((uint16_t)msg[2] << 8)) != AQARA_MFG_CODE) return false;
  if (msg[4] != 0x00) return false;
  if ((msg[5] | ((uint16_t)msg[6] << 8)) != H2_SAFE_ATTR_DIAG) return false;

  uint8_t buf[5 + 5 + 2 + 2 * H2_SAFE_RESET_HISTORY];
  uint8_t n = 0;
  buf[n++] = 0x04 | 0x08 | 0x10;                 // mfg-specific, server-to-client, no default rsp
  buf[n++] = (uint8_t)(AQARA_MFG_CODE & 0xFF);
  buf[n++] = (uint8_t)(AQARA_MFG_CODE >> 8);
  buf[n++] = msg[3];
  buf[n++] = 0x01;                               // Read Attributes Response
  buf[n++] = (uint8_t)(H2_SAFE_ATTR_DIAG & 0xFF);
  buf[n++] = (uint8_t)(H2_SAFE_ATTR_DIAG >> 8);
  buf[n++] = 0x00;                               // success
  buf[n++] = 0x41;                               // octet string
  buf[n++] = 2 + 2 * H2_SAFE_RESET_HISTORY;
  buf[n++] = safe_mode ? 1 : 0;
  buf[n++] = record.fails;
  for (int i = 0; i < H2_SAFE_RESET_HISTORY; i++) {
    buf[n++] = (uint8_t)(record.resets[i] & 0xFF);
    buf[n++] = (uint8_t)(record.resets[i] >> 8);
  }

  sl_zigbee_aps_frame_t aps = {
    .profileId           = HA_PROFILE_ID,
    .clusterId           = OPPLE_CLUSTER_ID,
    .sourceEndpoint      = endpoint,
    .destinationEndpoint = 1,
    .options             = SL_ZIGBEE_AF_DEFAULT_APS_OPTIONS
                         | SL_ZIGBEE_APS_OPTION_ENCRYPTION,
  };
  sl_zigbee_af_send_unicast(SL_ZIGBEE_OUTGOING_DIRECT, source_node, &aps, n, buf);
  return true;
}
