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
#define BUDGET_ACTIONS        16     // relay, level, LED, log and gesture calls per event
#define TIMER_MIN_MS          50
#define ZCL_PAYLOAD_MAX       64
#define BOOT_EVENT_DELAY_MS   500

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
static uint8_t actions_left;

// Public variables, outside events and the allowance for reacting to them (h2_rules.h)
#define REPORT_DELAY_MS       300      // collect variable changes before telling the hub
#define REACTION_TOKENS       4        // radio messages a rule may send in reaction ...
#define REACTION_REFILL_MS    2500     // ... refilled one at a time: 4 per 10 s sustained
#define EXT_QUEUE             4

static uint16_t public_mask;           // variables a program has declared public
static uint16_t dirty_mask;            // public variables changed by the program, not yet reported
static sl_zigbee_af_event_t report_event;
static sl_zigbee_af_event_t ext_event;
static struct { uint8_t type; int32_t value; } ext_queue[EXT_QUEUE];
static uint8_t ext_count;
static bool in_reaction;               // the running event came from outside, not from a button
static uint8_t reaction_tokens = REACTION_TOKENS;
static uint32_t reaction_refill_tick;
static uint32_t stat_dropped;          // messages and outside events dropped by the limits
static uint32_t stat_events, stat_handled, stat_faults;
static bool safe;                 // safe mode: programs can be uploaded but do not run
static uint8_t upload_result;     // result of the last commit
static uint16_t upload_detail;
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
  if (in_reaction) {
    // Messages sent in reaction to an outside event come from a small allowance, so a
    // rule that keeps reacting to its own effects slows to a trickle.
    uint32_t now = halCommonGetInt32uMillisecondTick();
    while (reaction_tokens < REACTION_TOKENS && now - reaction_refill_tick >= REACTION_REFILL_MS) {
      reaction_tokens++;
      reaction_refill_tick += REACTION_REFILL_MS;
    }
    if (reaction_tokens == REACTION_TOKENS) reaction_refill_tick = now;
    if (reaction_tokens == 0) {
      stat_dropped++;
      return -1;
    }
    reaction_tokens--;
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
  // Host functions that drive hardware or print are limited per event, like radio
  // messages: an event must stay short however the program loops, or it would starve
  // the watchdog.
  if (id == 1 || id == 3 || id == 6 || id == 7 || id == 12 || id == 13) {
    if (actions_left == 0) return (uint64_t)-1;
    actions_left--;
  }
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
      if (vars[a[0]] != (int32_t)a[1]) {
        vars[a[0]] = (int32_t)a[1];
        if (public_mask & (1u << a[0])) {          // tell the hub, once things settle
          dirty_mask |= (uint16_t)(1u << a[0]);
          if (!sl_zigbee_af_event_is_scheduled(&report_event)) {
            sl_zigbee_af_event_set_delay_ms(&report_event, REPORT_DELAY_MS);
          }
        }
      }
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
    case 14:  // var_public(mask)
      public_mask = (uint16_t)a[0];
      dirty_mask &= public_mask;
      return 0;
    case 13:  // max_clicks(button, clicks, wait)
      if (a[1] < 1 || a[1] > 3) return (uint64_t)-1;
      h2_rules_host_max_clicks((uint8_t)a[0], (uint8_t)a[1], a[2] != 0);
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
  in_reaction = (source == H2_RULES_SRC_SYSTEM
                 && (type == H2_RULES_EV_VAR || type == H2_RULES_EV_TRIGGER));
  messages_left = BUDGET_MESSAGES;
  actions_left = BUDGET_ACTIONS;
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

// Report the public variables the program changed to the hub, in one message.
static void report_handler(sl_zigbee_af_event_t *event)
{
  sl_zigbee_af_event_set_inactive(event);
  uint16_t mask = dirty_mask & public_mask;
  dirty_mask = 0;
  if (!mask || sl_zigbee_af_network_state() != SL_ZIGBEE_JOINED_NETWORK) return;

  uint8_t msg[5 + 7 * 8];
  uint8_t n = 0;
  msg[n++] = 0x04 | 0x08 | 0x10;      // global, manufacturer-specific, to client, no default response
  msg[n++] = 0x5F;                    // Aqara manufacturer code 0x115F
  msg[n++] = 0x11;
  msg[n++] = sl_zigbee_af_next_sequence();
  msg[n++] = 0x0A;                    // Report Attributes
  for (uint8_t i = 0; i < H2_RULES_VARS; i++) {
    if (!(mask & (1u << i))) continue;
    if (n + 7 > sizeof(msg)) {        // the rest goes in the next report
      dirty_mask |= (uint16_t)(mask & ~((1u << i) - 1));
      sl_zigbee_af_event_set_delay_ms(&report_event, REPORT_DELAY_MS);
      break;
    }
    uint16_t attr = (uint16_t)(H2_RULES_ATTR_VAR0 + i);
    msg[n++] = (uint8_t)attr;
    msg[n++] = (uint8_t)(attr >> 8);
    msg[n++] = 0x23;                  // uint32
    memcpy(&msg[n], &vars[i], 4);
    n += 4;
  }
  sl_zigbee_aps_frame_t aps;
  memset(&aps, 0, sizeof(aps));
  aps.profileId = 0x0104;
  aps.clusterId = 0xFCC0;
  aps.sourceEndpoint = 1;
  aps.destinationEndpoint = 1;
  aps.options = SL_ZIGBEE_APS_OPTION_ENABLE_ROUTE_DISCOVERY;
  (void)sl_zigbee_af_send_unicast(SL_ZIGBEE_OUTGOING_DIRECT, 0x0000, &aps, n, msg);
}

// Outside events are handed to the program from the main loop, one per pass, not from
// inside the message handler that received them.
static void ext_handler(sl_zigbee_af_event_t *event)
{
  sl_zigbee_af_event_set_inactive(event);
  if (ext_count == 0) return;
  uint8_t type = ext_queue[0].type;
  int32_t value = ext_queue[0].value;
  ext_count--;
  memmove(&ext_queue[0], &ext_queue[1], ext_count * sizeof(ext_queue[0]));
  (void)h2_rules_event(H2_RULES_SRC_SYSTEM, type, value);
  if (ext_count) sl_zigbee_af_event_set_active(&ext_event);
}

static void ext_post(uint8_t type, int32_t value)
{
  if (!active) return;
  if (ext_count >= EXT_QUEUE) {
    stat_dropped++;
    return;
  }
  ext_queue[ext_count].type = type;
  ext_queue[ext_count].value = value;
  ext_count++;
  sl_zigbee_af_event_set_active(&ext_event);
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
  public_mask = 0;
  dirty_mask = 0;
  ext_count = 0;
  for (uint8_t b = 0; b < 8; b++) {
    h2_rules_host_max_clicks(b, 1, false);   // gesture settings belong to the program
  }
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
  return h2_rules_upload_data_at(staging_got, data, length);
}

bool h2_rules_upload_data_at(uint16_t offset, const uint8_t *data, uint16_t length)
{
  // Data arrives in order. A repeat of bytes already received (a retried radio message)
  // is accepted and rewrites the same bytes; a gap is refused.
  if (staging_len == 0 || offset > staging_got || length > staging_len - offset) return false;
  memcpy(staging + offset, data, length);
  if ((uint16_t)(offset + length) > staging_got) staging_got = (uint16_t)(offset + length);
  return true;
}

static uint8_t commit(uint32_t *detail);

uint8_t h2_rules_upload_commit(uint32_t *detail)
{
  uint32_t d = 0;
  upload_result = commit(&d);
  upload_detail = (uint16_t)d;
  if (detail) *detail = d;
  return upload_result;
}

static uint8_t commit(uint32_t *detail)
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
  sl_zigbee_app_debug_println("Rules: installed %d bytes", code_len);
  if (!safe) {
    active = true;
    sl_zigbee_af_event_set_delay_ms(&boot_event, 100);
  }
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
  sl_zigbee_af_event_init(&report_event, report_handler);
  sl_zigbee_af_event_init(&ext_event, ext_handler);

  if (safe_mode) {
    safe = true;
    load_stored();     // so the stored program can be inspected; it does not run
    sl_zigbee_app_debug_println("Rules: off (safe mode)");
    return;
  }
  if (load_stored()) {
    active = true;
    sl_zigbee_af_event_set_delay_ms(&boot_event, BOOT_EVENT_DELAY_MS);
    sl_zigbee_app_debug_println("Rules: loaded %d bytes", code_len);
  }
}

// ---------------------------------------------------------------------------
// Access over Zigbee (attributes on the Opple cluster, see h2_rules.h)
// ---------------------------------------------------------------------------

bool h2_rules_attr_get(uint16_t attr_id, uint32_t *value)
{
  switch (attr_id) {
    case H2_RULES_ATTR_CONTROL: {
      uint32_t flags = (active ? 1u : 0u) | (staging_len ? 2u : 0u) | (safe ? 4u : 0u);
      *value = (flags << 24) | ((uint32_t)upload_result << 16)
             | (staging_len ? staging_got : upload_detail);
      return true;
    }
    case H2_RULES_ATTR_INFO:
      *value = code_len ? (((uint32_t)crc16(code, code_len) << 16) | code_len) : 0;
      return true;
    case H2_RULES_ATTR_DROPPED:
      *value = stat_dropped;
      return true;
    case H2_RULES_ATTR_FAULT:
      *value = ((uint32_t)last_fault << 24) | ((stat_faults > 255 ? 255u : stat_faults) << 16)
             | (last_fault_pc & 0xFFFF);
      return true;
    default:
      if (attr_id >= H2_RULES_ATTR_VAR0 && attr_id < H2_RULES_ATTR_VAR0 + H2_RULES_VARS
          && (public_mask & (1u << (attr_id - H2_RULES_ATTR_VAR0)))) {
        *value = (uint32_t)vars[attr_id - H2_RULES_ATTR_VAR0];
        return true;
      }
      return false;
  }
}

bool h2_rules_attr_write(uint16_t attr_id, uint8_t zcl_type, const uint8_t *data,
                         uint16_t length, bool *ok)
{
  *ok = false;
  if (attr_id == H2_RULES_ATTR_INFO || attr_id == H2_RULES_ATTR_FAULT
      || attr_id == H2_RULES_ATTR_DROPPED) return true;   // read only

  if (attr_id == H2_RULES_ATTR_TRIGGER
      || (attr_id >= H2_RULES_ATTR_VAR0 && attr_id < H2_RULES_ATTR_VAR0 + H2_RULES_VARS)) {
    if (zcl_type != 0x23 || length < 4 || !active) return true;    // uint32, program running
    int32_t v = (int32_t)((uint32_t)data[0] | ((uint32_t)data[1] << 8)
                          | ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24));
    if (attr_id == H2_RULES_ATTR_TRIGGER) {
      ext_post(H2_RULES_EV_TRIGGER, v);
      *ok = true;
      return true;
    }
    uint8_t index = (uint8_t)(attr_id - H2_RULES_ATTR_VAR0);
    if (!(public_mask & (1u << index))) return true;               // private: refused
    *ok = true;
    if (vars[index] != v) {            // writing the value it already has does nothing
      vars[index] = v;
      ext_post(H2_RULES_EV_VAR, index);
    }
    return true;
  }

  if (attr_id == H2_RULES_ATTR_CONTROL) {
    if (zcl_type != 0x23 || length < 4) return true;               // uint32
    uint16_t arg = (uint16_t)(data[0] | ((uint16_t)data[1] << 8));
    switch (data[3]) {
      case H2_RULES_OP_BEGIN:
        *ok = h2_rules_upload_begin(arg);
        break;
      case H2_RULES_OP_COMMIT:
        if (staging_len != 0 && staging_got == staging_len
            && crc16(staging, staging_len) != arg) {
          staging_len = 0;
          upload_result = 5;
          upload_detail = 0;
        } else {
          *ok = (h2_rules_upload_commit(NULL) == 0);
        }
        break;
      case H2_RULES_OP_ERASE:
        staging_len = 0;
        h2_rules_erase();
        *ok = true;
        break;
      default:
        break;
    }
    return true;
  }

  if (attr_id == H2_RULES_ATTR_DATA) {
    // Octet string: [string length][offset lo][offset hi][bytes...]
    if (zcl_type != 0x41 || length < 1 || data[0] < 3 || (uint16_t)(1 + data[0]) > length) return true;
    uint16_t offset = (uint16_t)(data[1] | ((uint16_t)data[2] << 8));
    *ok = h2_rules_upload_data_at(offset, &data[3], (uint16_t)(data[0] - 2));
    return true;
  }
  return false;
}
