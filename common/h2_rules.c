#include "app/framework/include/af.h"
#include "nvm3_default.h"

#include "h2_rules.h"
#include "h2_bpf.h"
#include "h2_variant.h"
#if H2_HAS_LED_ENDPOINTS
#include "h2_led_ep.h"
#endif

#define NVM3_KEY_RULES_HDR    0x0240
#define NVM3_KEY_RULES_DATA   0x0241       // .. 0x0241 + chunks
#define CHUNK_BYTES           192
#define MAX_CHUNKS            ((H2_RULES_MAX_BYTES + CHUNK_BYTES - 1) / CHUNK_BYTES)

#define BUDGET_INSTRUCTIONS   4000         // per event
#define BUDGET_MESSAGES       8            // radio messages per event
#define TIMER_MIN_MS          50
#define ZCL_PAYLOAD_MAX       64
#define BOOT_EVENT_DELAY_MS   3000

typedef struct {
  uint16_t length;
  uint16_t crc;
} rules_header_t;

// Layout must match struct h2_event in rules/h2_rules.h.
typedef struct {
  uint8_t  source;
  uint8_t  type;
  int32_t  value;
  uint32_t millis;
} rules_event_t;

static uint8_t code[H2_RULES_MAX_BYTES];
static uint16_t code_len;
static bool active;

static uint8_t staging[H2_RULES_MAX_BYTES];
static uint16_t staging_len;
static uint16_t staging_got;

static int32_t vars[H2_RULES_VARS];
static sl_zigbee_af_event_t timers[H2_RULES_TIMERS];
static sl_zigbee_af_event_t boot_event;

static h2_bpf_vm_t vm;
static bool running;
static uint8_t messages_left;
static uint32_t stat_events, stat_handled, stat_faults;
static uint8_t last_fault;
static uint32_t last_fault_pc;

static uint16_t crc16(const uint8_t *data, uint16_t len)
{
  uint16_t crc = 0xFFFF;
  while (len--) {
    crc ^= *data++;
    for (uint8_t i = 0; i < 8; i++) {
      crc = (crc & 1) ? (uint16_t)((crc >> 1) ^ 0xA001) : (uint16_t)(crc >> 1);
    }
  }
  return crc;
}

// ---------------------------------------------------------------------------
// Zigbee output
// ---------------------------------------------------------------------------

static long send_zcl(bool group, uint16_t dest, uint8_t dest_endpoint, uint16_t cluster,
                     uint8_t command, const uint8_t *payload, uint8_t len)
{
  if (messages_left == 0 || sl_zigbee_af_network_state() != SL_ZIGBEE_JOINED_NETWORK) {
    return -1;
  }
  messages_left--;

  uint8_t msg[3 + ZCL_PAYLOAD_MAX];
  msg[0] = ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER
           | ZCL_DISABLE_DEFAULT_RESPONSE_MASK;
  msg[1] = sl_zigbee_af_next_sequence();
  msg[2] = command;
  if (len) memcpy(msg + 3, payload, len);

  sl_zigbee_aps_frame_t aps;
  memset(&aps, 0, sizeof(aps));
  aps.profileId = 0x0104;
  aps.clusterId = cluster;
  aps.sourceEndpoint = h2_rules_host_source_endpoint();
  aps.destinationEndpoint = group ? 0xFF : dest_endpoint;
  aps.options = SL_ZIGBEE_APS_OPTION_ENABLE_ROUTE_DISCOVERY;

  sl_status_t status;
  if (group) {
    status = sl_zigbee_af_send_multicast(dest, SL_ZIGBEE_NULL_NODE_ID, 0, &aps, (uint16_t)(3 + len), msg);
  } else {
    aps.options |= SL_ZIGBEE_APS_OPTION_RETRY;
    status = sl_zigbee_af_send_unicast(SL_ZIGBEE_OUTGOING_DIRECT, dest, &aps, (uint16_t)(3 + len), msg);
  }
  sl_zigbee_app_debug_println("Rules: zcl %s 0x%04X cluster 0x%04X cmd 0x%02X len %d -> 0x%02X",
                               group ? "group" : "node", dest, cluster, command, len, status);
  return status == SL_STATUS_OK ? 0 : -1;
}

// ---------------------------------------------------------------------------
// Host functions (numbers match rules/h2_rules.h)
// ---------------------------------------------------------------------------

static uint64_t helper(h2_bpf_vm_t *m, uint32_t id, const uint64_t a[5], bool *ok)
{
  switch (id) {
    case 1:   // relay_set(gang, mode)
      if (a[0] >= H2_SWITCH_GANG_COUNT || a[1] > 2) return (uint64_t)-1;
      h2_rules_host_relay_set((uint8_t)a[0], (uint8_t)a[1]);
      return 0;
    case 2:   // relay_get(gang)
      return (a[0] < H2_SWITCH_GANG_COUNT && h2_rules_host_relay_get((uint8_t)a[0])) ? 1 : 0;
    case 3:   // level_set(gang, level)
      if (a[0] >= H2_SWITCH_GANG_COUNT || a[1] < 1 || a[1] > 254) return (uint64_t)-1;
      h2_rules_host_level_set((uint8_t)a[0], (uint8_t)a[1]);
      return 0;
    case 4: { // scene_recall(group, scene)
      uint8_t p[3] = { (uint8_t)a[0], (uint8_t)(a[0] >> 8), (uint8_t)a[1] };
      return (uint64_t)send_zcl(true, (uint16_t)a[0], 0, ZCL_SCENES_CLUSTER_ID,
                                ZCL_RECALL_SCENE_COMMAND_ID, p, sizeof(p));
    }
    case 5:   // zcl_group(group, cluster, command, payload, len)
      if (a[4] > ZCL_PAYLOAD_MAX
          || (a[4] > 0 && !h2_bpf_check_ptr(m, a[3], (uint32_t)a[4], false))) {
        *ok = false;
        return 0;
      }
      return (uint64_t)send_zcl(true, (uint16_t)a[0], 0, (uint16_t)a[1], (uint8_t)a[2],
                                (const uint8_t *)(uintptr_t)a[3], (uint8_t)a[4]);
    case 6:   // led_set(led, red, blue)
#if H2_HAS_LED_ENDPOINTS
      if (a[0] >= h2_led_ep_count()) return (uint64_t)-1;
      h2_led_ep_set_channels((uint8_t)a[0], a[1] > 255 ? 255 : (uint8_t)a[1],
                             a[2] > 255 ? 255 : (uint8_t)a[2]);
      return 0;
#else
      return (uint64_t)-1;
#endif
    case 7:   // led_release(led)
#if H2_HAS_LED_ENDPOINTS
      if (a[0] >= h2_led_ep_count()) return (uint64_t)-1;
      h2_led_ep_release((uint8_t)a[0]);
      return 0;
#else
      return (uint64_t)-1;
#endif
    case 8:   // var_get(index)
      return a[0] < H2_RULES_VARS ? (uint64_t)(int64_t)vars[a[0]] : 0;
    case 9:   // var_set(index, value)
      if (a[0] >= H2_RULES_VARS) return (uint64_t)-1;
      vars[a[0]] = (int32_t)a[1];
      return 0;
    case 10:  // timer_start(id, ms)
      if (a[0] >= H2_RULES_TIMERS) return (uint64_t)-1;
      sl_zigbee_af_event_set_delay_ms(&timers[a[0]],
                                      a[1] < TIMER_MIN_MS ? TIMER_MIN_MS
                                      : (a[1] > 3600000UL ? 3600000UL : (uint32_t)a[1]));
      return 0;
    case 11:  // timer_stop(id)
      if (a[0] >= H2_RULES_TIMERS) return (uint64_t)-1;
      sl_zigbee_af_event_set_inactive(&timers[a[0]]);
      return 0;
    case 12:  // log_value(tag, value)
      sl_zigbee_app_debug_println("Rules: log %ld = %ld", (long)a[0], (long)a[1]);
      return 0;
    default:
      *ok = false;
      return 0;
  }
}

// ---------------------------------------------------------------------------
// Running
// ---------------------------------------------------------------------------

bool h2_rules_active(void)
{
  return active;
}

bool h2_rules_event(uint8_t source, uint8_t type, int32_t value)
{
  if (!active || running) return false;

  rules_event_t ev;
  memset(&ev, 0, sizeof(ev));
  ev.source = source;
  ev.type = type;
  ev.value = value;
  ev.millis = halCommonGetInt32uMillisecondTick();

  h2_bpf_region_t region = { (const uint8_t *)&ev, sizeof(ev), false };
  vm.code = code;
  vm.code_len = code_len;
  vm.regions = &region;
  vm.region_count = 1;
  vm.helper = helper;
  vm.budget = BUDGET_INSTRUCTIONS;

  running = true;
  messages_left = BUDGET_MESSAGES;
  uint64_t result = 0;
  h2_bpf_status_t status = h2_bpf_run(&vm, (uint64_t)(uintptr_t)&ev, &result);
  running = false;

  stat_events++;
  if (status != H2_BPF_OK) {
    stat_faults++;
    last_fault = (uint8_t)status;
    last_fault_pc = vm.fault_pc;
    sl_zigbee_app_debug_println("Rules: FAULT %d at instruction %lu (event %d/%d)",
                                 status, (unsigned long)vm.fault_pc, source, type);
    return false;
  }
  if (result != 0) stat_handled++;
  return result != 0;
}

static void timer_handler(sl_zigbee_af_event_t *event)
{
  uint8_t id = (uint8_t)(event - timers);
  sl_zigbee_af_event_set_inactive(event);
  (void)h2_rules_event(H2_RULES_SRC_TIMER, H2_RULES_EV_TIMER, id);
}

static void boot_handler(sl_zigbee_af_event_t *event)
{
  sl_zigbee_af_event_set_inactive(event);
  (void)h2_rules_event(H2_RULES_SRC_SYSTEM, H2_RULES_EV_BOOT, 0);
}

static void stop_program(void)
{
  active = false;
  for (uint8_t i = 0; i < H2_RULES_TIMERS; i++) {
    sl_zigbee_af_event_set_inactive(&timers[i]);
  }
  memset(vars, 0, sizeof(vars));
}

// ---------------------------------------------------------------------------
// Storage and upload
// ---------------------------------------------------------------------------

static bool load_stored(void)
{
  rules_header_t hdr;
  if (nvm3_readData(nvm3_defaultHandle, NVM3_KEY_RULES_HDR, &hdr, sizeof(hdr)) != ECODE_NVM3_OK
      || hdr.length == 0 || hdr.length > H2_RULES_MAX_BYTES) {
    return false;
  }
  for (uint16_t off = 0, i = 0; off < hdr.length; off += CHUNK_BYTES, i++) {
    uint16_t n = (uint16_t)(hdr.length - off);
    if (n > CHUNK_BYTES) n = CHUNK_BYTES;
    if (nvm3_readData(nvm3_defaultHandle, NVM3_KEY_RULES_DATA + i, code + off, n) != ECODE_NVM3_OK) {
      return false;
    }
  }
  if (crc16(code, hdr.length) != hdr.crc
      || h2_bpf_verify(code, hdr.length, NULL) != H2_BPF_OK) {
    return false;
  }
  code_len = hdr.length;
  return true;
}

void h2_rules_erase(void)
{
  stop_program();
  code_len = 0;
  nvm3_deleteObject(nvm3_defaultHandle, NVM3_KEY_RULES_HDR);
  for (uint8_t i = 0; i < MAX_CHUNKS; i++) {
    nvm3_deleteObject(nvm3_defaultHandle, NVM3_KEY_RULES_DATA + i);
  }
  sl_zigbee_app_debug_println("Rules: erased");
}

bool h2_rules_upload_begin(uint16_t length)
{
  staging_got = 0;
  staging_len = 0;
  if (length == 0 || length > H2_RULES_MAX_BYTES || (length & 7)) return false;
  staging_len = length;
  return true;
}

bool h2_rules_upload_data(const uint8_t *data, uint16_t length)
{
  if (staging_len == 0 || length > staging_len - staging_got) return false;
  memcpy(staging + staging_got, data, length);
  staging_got = (uint16_t)(staging_got + length);
  return true;
}

uint8_t h2_rules_upload_commit(uint32_t *detail)
{
  uint32_t bad_pc = 0;
  if (detail) *detail = 0;
  if (staging_len == 0) return 1;
  if (staging_got != staging_len) return 2;
  if (h2_bpf_verify(staging, staging_len, &bad_pc) != H2_BPF_OK) {
    if (detail) *detail = bad_pc;
    staging_len = 0;
    return 3;
  }

  // Invalidate the stored copy first, so a power cut mid-write leaves "no rules" and
  // never a mix of old and new chunks.
  nvm3_deleteObject(nvm3_defaultHandle, NVM3_KEY_RULES_HDR);
  for (uint16_t off = 0, i = 0; off < staging_len; off += CHUNK_BYTES, i++) {
    uint16_t n = (uint16_t)(staging_len - off);
    if (n > CHUNK_BYTES) n = CHUNK_BYTES;
    if (nvm3_writeData(nvm3_defaultHandle, NVM3_KEY_RULES_DATA + i, staging + off, n) != ECODE_NVM3_OK) {
      staging_len = 0;
      return 4;
    }
    halResetWatchdog();
  }
  rules_header_t hdr = { staging_len, crc16(staging, staging_len) };
  if (nvm3_writeData(nvm3_defaultHandle, NVM3_KEY_RULES_HDR, &hdr, sizeof(hdr)) != ECODE_NVM3_OK) {
    staging_len = 0;
    return 4;
  }

  stop_program();
  memcpy(code, staging, staging_len);
  code_len = staging_len;
  staging_len = 0;
  active = true;
  sl_zigbee_app_debug_println("Rules: installed %d bytes", code_len);
  sl_zigbee_af_event_set_delay_ms(&boot_event, 100);
  return 0;
}

void h2_rules_print_info(void)
{
  sl_zigbee_app_debug_println("Rules: %s, %d bytes, events %lu handled %lu faults %lu (last %d at %lu)",
                               active ? "active" : "off", code_len,
                               (unsigned long)stat_events, (unsigned long)stat_handled,
                               (unsigned long)stat_faults, last_fault, (unsigned long)last_fault_pc);
}

void h2_rules_init(bool safe_mode)
{
  for (uint8_t i = 0; i < H2_RULES_TIMERS; i++) {
    sl_zigbee_af_event_init(&timers[i], timer_handler);
  }
  sl_zigbee_af_event_init(&boot_event, boot_handler);

  if (safe_mode) {
    sl_zigbee_app_debug_println("Rules: off (safe mode)");
    return;
  }
  if (load_stored()) {
    active = true;
    sl_zigbee_af_event_set_delay_ms(&boot_event, BOOT_EVENT_DELAY_MS);
    sl_zigbee_app_debug_println("Rules: loaded %d bytes", code_len);
  }
}
