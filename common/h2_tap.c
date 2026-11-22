#include "h2_build.h"
#include "h2_tap.h"

#if H2_BENCH

#include "app/framework/include/af.h"
#include "app/framework/util/common.h"
#include "sl_sleeptimer.h"

#include "h2_opple.h"

#define TAP_QUEUE_LEN      8
#define TAP_MIN_GAP_MS     60     // at most ~16 reports per second

#define ZCL_FC_MFG_SPECIFIC        0x04
#define ZCL_FC_DIRECTION_S2C       0x08
#define ZCL_FC_DISABLE_DEFAULT_RSP 0x10
#define ZCL_CMD_REPORT_ATTRIBUTES  0x0A
#define ZCL_TYPE_OCTET_STRING      0x41

typedef struct {
  uint8_t dir;
  uint8_t counter;
  uint8_t len;
  uint8_t data[H2_TAP_MAX_FRAME];
} tap_entry_t;

static uint8_t tap_mode = H2_TAP_MODE_OFF;
static tap_entry_t queue[TAP_QUEUE_LEN];
static uint8_t q_head;          // next entry to send
static uint8_t q_count;
static uint8_t frame_counter;
static uint8_t skipped_poll_seq;
static bool skipped_poll_pending;
static uint32_t last_send_tick;

void h2_tap_set_mode(uint8_t mode)
{
  tap_mode = mode;
  if (mode == H2_TAP_MODE_OFF) {
    q_count = 0;
  }
  skipped_poll_pending = false;
}

uint8_t h2_tap_get_mode(void)
{
  return tap_mode;
}

void h2_tap_record(uint8_t dir, const uint8_t *frame, uint16_t len)
{
  if (tap_mode == H2_TAP_MODE_OFF || len < 5) {
    return;
  }

  if (tap_mode == H2_TAP_MODE_NO_POLLS) {
    if (dir == 0 && frame[4] == 0x01) {          // our READ request
      skipped_poll_seq = frame[3];
      skipped_poll_pending = true;
      return;
    }
    if (dir == 1 && skipped_poll_pending && frame[3] == skipped_poll_seq
        && frame[4] != 0x05) {                   // its reply (never an unsolicited report)
      skipped_poll_pending = false;
      return;
    }
  }

  uint8_t counter = frame_counter++;
  if (q_count >= TAP_QUEUE_LEN) {
    return;                                      // full: drop, the counter gap shows it
  }
  tap_entry_t *e = &queue[(q_head + q_count) % TAP_QUEUE_LEN];
  e->dir = dir;
  e->counter = counter;
  e->len = (len > H2_TAP_MAX_FRAME) ? H2_TAP_MAX_FRAME : (uint8_t)len;
  memcpy(e->data, frame, e->len);
  q_count++;
}

void h2_tap_tick(void)
{
  if (q_count == 0) {
    return;
  }
  if (sl_zigbee_af_network_state() != SL_ZIGBEE_JOINED_NETWORK) {
    q_count = 0;
    return;
  }
  uint32_t now = sl_sleeptimer_get_tick_count();
  if (sl_sleeptimer_tick_to_ms(now - last_send_tick) < TAP_MIN_GAP_MS) {
    return;
  }

  const tap_entry_t *e = &queue[q_head];
  uint8_t buf[5 + 4 + 2 + H2_TAP_MAX_FRAME];
  uint8_t n = 0;
  buf[n++] = ZCL_FC_MFG_SPECIFIC | ZCL_FC_DIRECTION_S2C | ZCL_FC_DISABLE_DEFAULT_RSP;
  buf[n++] = (uint8_t)(AQARA_MFG_CODE & 0xFF);
  buf[n++] = (uint8_t)(AQARA_MFG_CODE >> 8);
  buf[n++] = sl_zigbee_af_next_sequence();
  buf[n++] = ZCL_CMD_REPORT_ATTRIBUTES;
  buf[n++] = (uint8_t)(H2_TAP_ATTR_FRAME & 0xFF);
  buf[n++] = (uint8_t)(H2_TAP_ATTR_FRAME >> 8);
  buf[n++] = ZCL_TYPE_OCTET_STRING;
  buf[n++] = (uint8_t)(2 + e->len);
  buf[n++] = e->dir;
  buf[n++] = e->counter;
  memcpy(&buf[n], e->data, e->len);
  n += e->len;

  sl_zigbee_aps_frame_t aps = {
    .profileId           = HA_PROFILE_ID,
    .clusterId           = OPPLE_CLUSTER_ID,
    .sourceEndpoint      = 1,
    .destinationEndpoint = 1,
    .options             = SL_ZIGBEE_AF_DEFAULT_APS_OPTIONS
                         | SL_ZIGBEE_APS_OPTION_ENCRYPTION,
  };
  if (sl_zigbee_af_send_unicast(SL_ZIGBEE_OUTGOING_DIRECT, 0x0000, &aps, n, buf)
      == SL_STATUS_OK) {
    q_head = (q_head + 1) % TAP_QUEUE_LEN;
    q_count--;
  }
  last_send_tick = now;
}

#else  // !H2_BENCH: the tap does not exist in release builds

void h2_tap_set_mode(uint8_t mode) { (void)mode; }
uint8_t h2_tap_get_mode(void) { return H2_TAP_MODE_OFF; }
void h2_tap_record(uint8_t dir, const uint8_t *frame, uint16_t len) { (void)dir; (void)frame; (void)len; }
void h2_tap_tick(void) {}

#endif
