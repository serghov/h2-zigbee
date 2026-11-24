#include "app/framework/include/af.h"
#include "nvm3_default.h"
#include "app/util/zigbee-framework/zigbee-device-common.h"

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
  uint16_t cluster;     // H2_RULES_EV_REPORT: which attribute of the other device
  uint16_t attr;
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

// State other devices report to this one (h2_rules.h). One slot per device and watched
// attribute holds the newest value, so memory is fixed and a burst of reports collapses
// into the latest value.
#define PEERS                 8
#define WATCHES               4
#define REMOTE_MIN_GAP_MS     250      // per slot: at most one event this often

static struct { uint16_t cluster, attr; } watches[WATCHES];
static uint8_t watch_count;
#define PEER_SILENT_MS        (60UL * 60UL * 1000UL)   // a device not heard for this long is dropped
#define PEER_AGE_CHECK_MS     60000
static uint16_t peer_node[PEERS];      // short address
static bool     peer_used[PEERS];
static uint8_t  peer_endpoint[PEERS];  // the endpoint its reports come from
static uint32_t peer_heard[PEERS];     // when it last sent anything we watch
static bool     timer_reaction[H2_RULES_TIMERS];   // the timer was started while reacting
static sl_zigbee_af_event_t peer_age_event;
static uint8_t  found_mask;            // devices the program has not been told about yet

// Binding on request of the program (helper report_here): a device is asked to report a
// cluster to this one from then on (a ZDO bind), so nobody has to set up bindings on the
// hub. The firmware does the mechanics: it finds the device's long address first, then
// sends the request. Asking again for a binding that exists is harmless.
#define BIND_CLUSTERS         4
#define BIND_STEP_MS          300
#define BIND_ADDRESS_TRIES    5
static struct {
  uint8_t  eui[8];
  bool     have_eui;
  uint16_t cluster[BIND_CLUSTERS];     // clusters still to be bound
  uint8_t  wanted;                     // how many of them
  uint8_t  tries;
} peer_bind[PEERS];
static sl_zigbee_af_event_t bind_event;
static struct {
  int32_t  value;
  uint32_t delivered_at;
  bool     known;                      // a value has been delivered to the program
  bool     dirty;                      // a newer value is waiting
  int32_t  pending;
} remote_slot[PEERS][WATCHES];
static sl_zigbee_af_event_t remote_event;
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

static bool run_event(uint8_t source, uint8_t type, int32_t value, uint16_t cluster, uint16_t attr,
                      bool reaction);

// ---------------------------------------------------------------------------
// Zigbee output
// ---------------------------------------------------------------------------

// Radio messages sent in reaction to an outside event (and by timers started from one)
// come from a small allowance, so a rule that keeps reacting to its own effects slows to
// a trickle. Returns false when the allowance is used up.
static bool reaction_allows(void)
{
  if (!in_reaction) return true;
  uint32_t now = halCommonGetInt32uMillisecondTick();
  while (reaction_tokens < REACTION_TOKENS && now - reaction_refill_tick >= REACTION_REFILL_MS) {
    reaction_tokens++;
    reaction_refill_tick += REACTION_REFILL_MS;
  }
  if (reaction_tokens == REACTION_TOKENS) reaction_refill_tick = now;
  if (reaction_tokens == 0) {
    stat_dropped++;
    return false;
  }
  reaction_tokens--;
  return true;
}

static long send_zcl_frame(bool group, uint16_t dest, uint8_t dest_endpoint, uint16_t cluster,
                           uint8_t command, bool global, const uint8_t *payload, uint8_t len);

static long send_zcl(bool group, uint16_t dest, uint8_t dest_endpoint, uint16_t cluster,
                     uint8_t command, const uint8_t *payload, uint8_t len)
{
  return send_zcl_frame(group, dest, dest_endpoint, cluster, command, false, payload, len);
}

// global = a general ZCL command (read, configure reporting, ...), not one of the cluster's own.
static long send_zcl_frame(bool group, uint16_t dest, uint8_t dest_endpoint, uint16_t cluster,
                           uint8_t command, bool global, const uint8_t *payload, uint8_t len)
{
  if (messages_left == 0 || sl_zigbee_af_network_state() != SL_ZIGBEE_JOINED_NETWORK) {
    return -1;
  }
  if (!reaction_allows()) return -1;
  messages_left--;

  uint8_t msg[3 + ZCL_PAYLOAD_MAX];
  msg[0] = (global ? ZCL_GLOBAL_COMMAND : ZCL_CLUSTER_SPECIFIC_COMMAND)
           | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER | ZCL_DISABLE_DEFAULT_RESPONSE_MASK;
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
    case 18: { // report_here(device, cluster): ask that device to report the cluster to us
      uint8_t p = (uint8_t)a[0];
      if (a[0] >= PEERS || !peer_used[p]) return (uint64_t)-1;
      for (uint8_t i = 0; i < peer_bind[p].wanted; i++) {
        if (peer_bind[p].cluster[i] == (uint16_t)a[1]) return 0;   // already queued
      }
      if (peer_bind[p].wanted >= BIND_CLUSTERS) return (uint64_t)-1;
      peer_bind[p].cluster[peer_bind[p].wanted++] = (uint16_t)a[1];
      if (!sl_zigbee_af_event_is_scheduled(&bind_event)) {
        sl_zigbee_af_event_set_delay_ms(&bind_event, BIND_STEP_MS);
      }
      return 0;
    }
    case 17: { // zcl_send(dest, cluster, command | flags, payload, len)
      if (a[4] > ZCL_PAYLOAD_MAX
          || (a[4] > 0 && !h2_bpf_check_ptr(m, a[3], (uint32_t)a[4], false))) {
        *ok = false;
        return 0;
      }
      bool global = (a[2] & 0x100) != 0;
      if (a[0] & 0x10000) {            // one device this program has heard from
        uint8_t p = (uint8_t)(a[0] & 0xFF);
        if (p >= PEERS || !peer_used[p]) return (uint64_t)-1;
        return (uint64_t)send_zcl_frame(false, peer_node[p], peer_endpoint[p], (uint16_t)a[1],
                                        (uint8_t)a[2], global,
                                        (const uint8_t *)(uintptr_t)a[3], (uint8_t)a[4]);
      }
      return (uint64_t)send_zcl_frame(true, (uint16_t)a[0], 0, (uint16_t)a[1], (uint8_t)a[2], global,
                                      (const uint8_t *)(uintptr_t)a[3], (uint8_t)a[4]);
    }
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
      timer_reaction[a[0]] = in_reaction;
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
    case 15:  // watch(cluster, attribute)
      for (uint8_t i = 0; i < watch_count; i++) {
        if (watches[i].cluster == (uint16_t)a[0] && watches[i].attr == (uint16_t)a[1]) return i;
      }
      if (watch_count >= WATCHES) return (uint64_t)-1;
      watches[watch_count].cluster = (uint16_t)a[0];
      watches[watch_count].attr = (uint16_t)a[1];
      return watch_count++;
    case 16: { // group_read(group, cluster, attribute): members answer with their value
      if (messages_left == 0 || sl_zigbee_af_network_state() != SL_ZIGBEE_JOINED_NETWORK
          || !reaction_allows()) {
        return (uint64_t)-1;
      }
      messages_left--;
      uint8_t msg[5] = { ZCL_GLOBAL_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER
                         | ZCL_DISABLE_DEFAULT_RESPONSE_MASK,
                         sl_zigbee_af_next_sequence(), 0x00 /* Read Attributes */,
                         (uint8_t)a[2], (uint8_t)(a[2] >> 8) };
      sl_zigbee_aps_frame_t aps;
      memset(&aps, 0, sizeof(aps));
      aps.profileId = 0x0104;
      aps.clusterId = (uint16_t)a[1];
      aps.sourceEndpoint = h2_rules_host_source_endpoint();
      aps.destinationEndpoint = 0xFF;
      aps.options = SL_ZIGBEE_APS_OPTION_ENABLE_ROUTE_DISCOVERY;
      return sl_zigbee_af_send_multicast((uint16_t)a[0], SL_ZIGBEE_NULL_NODE_ID, 0, &aps,
                                         sizeof(msg), msg) == SL_STATUS_OK ? 0 : (uint64_t)-1;
    }
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
  return run_event(source, type, value, 0, 0, false);
}

static bool run_event(uint8_t source, uint8_t type, int32_t value, uint16_t cluster, uint16_t attr,
                      bool reaction)
{
  if (!active || running) return false;

  rules_event_t ev;
  memset(&ev, 0, sizeof(ev));
  ev.source = source;
  ev.type = type;
  ev.value = value;
  ev.cluster = cluster;
  ev.attr = attr;
  ev.millis = halCommonGetInt32uMillisecondTick();

  h2_bpf_region_t region = { (const uint8_t *)&ev, sizeof(ev), false };
  h2_bpf_image_t image;
  if (!h2_bpf_parse(code, code_len, &image)) return false;   // was checked when installed
  vm.code = image.code;
  vm.code_len = image.code_len;
  vm.data = image.data;
  vm.data_len = image.data_len;
  vm.regions = &region;
  vm.region_count = 1;
  vm.helper = helper;
  vm.budget = BUDGET_INSTRUCTIONS;

  running = true;
  in_reaction = reaction || (type == H2_RULES_EV_REPORT) || (type == H2_RULES_EV_LOST)
                || (type == H2_RULES_EV_FOUND)
                || (source == H2_RULES_SRC_SYSTEM
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
  (void)run_event(H2_RULES_SRC_TIMER, H2_RULES_EV_TIMER, id, 0, 0, timer_reaction[id]);
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
    msg[n++] = 0x2B;                  // int32
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

// ---------------------------------------------------------------------------
// Reports from other devices
// ---------------------------------------------------------------------------

// Hand waiting values to the program: at most one per pass, each slot rate-limited.
static void remote_handler(sl_zigbee_af_event_t *event)
{
  sl_zigbee_af_event_set_inactive(event);
  if (!active) return;
  for (uint8_t p = 0; p < PEERS; p++) {             // newly heard devices first
    if (found_mask & (1u << p)) {
      found_mask &= (uint8_t)~(1u << p);
      if (peer_used[p]) {
        (void)run_event((uint8_t)(H2_RULES_SRC_REMOTE0 + p), H2_RULES_EV_FOUND, 0, 0, 0, true);
        sl_zigbee_af_event_set_active(&remote_event);  // values on the next pass
        return;
      }
    }
  }
  uint32_t now = halCommonGetInt32uMillisecondTick();
  uint32_t soonest = 0xFFFFFFFF;
  bool delivered = false;
  for (uint8_t p = 0; p < PEERS; p++) {
    if (!peer_used[p]) continue;
    for (uint8_t w = 0; w < watch_count; w++) {
      if (!remote_slot[p][w].dirty) continue;
      uint32_t since = now - remote_slot[p][w].delivered_at;
      if (remote_slot[p][w].known && since < REMOTE_MIN_GAP_MS) {
        if (REMOTE_MIN_GAP_MS - since < soonest) soonest = REMOTE_MIN_GAP_MS - since;
        continue;
      }
      if (delivered) {              // one event per pass; come back for the next
        soonest = 0;
        continue;
      }
      remote_slot[p][w].dirty = false;
      remote_slot[p][w].known = true;
      remote_slot[p][w].value = remote_slot[p][w].pending;
      remote_slot[p][w].delivered_at = now;
      delivered = true;
      (void)run_event((uint8_t)(H2_RULES_SRC_REMOTE0 + p), H2_RULES_EV_REPORT,
                      remote_slot[p][w].value, watches[w].cluster, watches[w].attr, true);
    }
  }
  if (soonest != 0xFFFFFFFF) {
    sl_zigbee_af_event_set_delay_ms(&remote_event, soonest ? soonest : 1);
  }
}

// Forget a device: free its slot and tell the program, so it can drop what it knew.
static void peer_drop(uint8_t p)
{
  if (!peer_used[p]) return;
  peer_used[p] = false;
  memset(&peer_bind[p], 0, sizeof(peer_bind[p]));
  memset(remote_slot[p], 0, sizeof(remote_slot[p]));
  (void)run_event((uint8_t)(H2_RULES_SRC_REMOTE0 + p), H2_RULES_EV_LOST, 0, 0, 0, true);
}

// A device whose long address matches an older entry has come back under a new short
// address: the older entry is stale.
static void peer_same_device(uint8_t p)
{
  for (uint8_t q = 0; q < PEERS; q++) {
    if (q != p && peer_used[q] && peer_bind[q].have_eui
        && memcmp(peer_bind[q].eui, peer_bind[p].eui, 8) == 0) {
      peer_drop(q);
    }
  }
}

// Devices that have been silent for a long time are dropped. Lamps report at least every
// 15 minutes with the usual reporting setup, so an hour of silence means gone or renumbered.
static void peer_age_handler(sl_zigbee_af_event_t *event)
{
  sl_zigbee_af_event_set_inactive(event);
  if (!active) return;
  uint32_t now = halCommonGetInt32uMillisecondTick();
  bool any = false;
  for (uint8_t p = 0; p < PEERS; p++) {
    if (!peer_used[p]) continue;
    if (now - peer_heard[p] >= PEER_SILENT_MS) peer_drop(p);
    else any = true;
  }
  if (any) sl_zigbee_af_event_set_delay_ms(&peer_age_event, PEER_AGE_CHECK_MS);
}

// One step of self-binding per pass: find the device's long address, then send one bind
// request per watched cluster.
static void bind_handler(sl_zigbee_af_event_t *event)
{
  sl_zigbee_af_event_set_inactive(event);
  if (!active) return;
  if (sl_zigbee_af_network_state() != SL_ZIGBEE_JOINED_NETWORK) {
    sl_zigbee_af_event_set_delay_ms(&bind_event, 5000);        // try again once back on the network
    return;
  }
  for (uint8_t p = 0; p < PEERS; p++) {
    if (!peer_used[p] || !peer_bind[p].wanted) continue;
    if (!peer_bind[p].have_eui) {
      if (sl_zigbee_lookup_eui64_by_node_id(peer_node[p], peer_bind[p].eui) == SL_STATUS_OK) {
        peer_bind[p].have_eui = true;
        peer_same_device(p);
      } else if (peer_bind[p].tries++ < BIND_ADDRESS_TRIES) {
        (void)sl_zigbee_ieee_address_request(peer_node[p], false, 0, SL_ZIGBEE_APS_OPTION_RETRY);
        sl_zigbee_af_event_set_delay_ms(&bind_event, 1500);   // the answer comes as a ZDO message
        return;
      } else {
        peer_bind[p].wanted = 0;                               // give up on this device
        continue;
      }
    }
    uint16_t cluster = peer_bind[p].cluster[--peer_bind[p].wanted];
    sl_802154_long_addr_t self;
    sl_zigbee_af_get_eui64(self);
    sl_status_t st = sl_zigbee_bind_request(peer_node[p], peer_bind[p].eui, peer_endpoint[p],
                                            cluster, UNICAST_BINDING, self, 0,
                                            H2_RULES_REPORT_ENDPOINT, SL_ZIGBEE_APS_OPTION_RETRY);
    sl_zigbee_app_debug_println("Rules: asked node 0x%04X to report cluster 0x%04X here -> 0x%02X",
                                 peer_node[p], cluster, st);
    sl_zigbee_af_event_set_delay_ms(&bind_event, BIND_STEP_MS);
    return;
  }
}

// ZDO messages: the answer to an address request carries the long address.
bool sl_zigbee_af_pre_zdo_message_received_cb(sl_802154_short_addr_t node, sl_zigbee_aps_frame_t *aps,
                                              uint8_t *message, uint16_t length)
{
  if (aps->clusterId == 0x8001 && length >= 12 && message[1] == 0x00) {   // IEEE_addr_rsp, success
    // Only the answer we asked for: from the device itself, about itself, while a request
    // to it is outstanding.
    uint16_t about = (uint16_t)(message[10] | ((uint16_t)message[11] << 8));
    for (uint8_t p = 0; p < PEERS; p++) {
      if (peer_used[p] && peer_node[p] == about && node == about
          && peer_bind[p].tries > 0 && !peer_bind[p].have_eui) {
        memcpy(peer_bind[p].eui, &message[2], 8);
        peer_bind[p].have_eui = true;
        peer_same_device(p);
      }
    }
  }
  return false;
}

static void remote_value(uint16_t node, uint8_t endpoint, bool answered_read,
                         uint16_t cluster, uint16_t attr, int32_t value)
{
  uint8_t w, p;
  for (w = 0; w < watch_count; w++) {
    if (watches[w].cluster == cluster && watches[w].attr == attr) break;
  }
  if (w == watch_count) return;       // the program did not ask for this attribute
  for (p = 0; p < PEERS; p++) {
    if (peer_used[p] && peer_node[p] == node) break;
  }
  if (p == PEERS) {
    for (p = 0; p < PEERS; p++) {
      if (!peer_used[p]) break;
    }
    if (p == PEERS) {                 // table full: the newcomer is ignored
      stat_dropped++;
      return;
    }
    peer_used[p] = true;
    peer_node[p] = node;
    peer_endpoint[p] = endpoint;
    found_mask |= (uint8_t)(1u << p);  // the program is told before the value arrives
    memset(&peer_bind[p], 0, sizeof(peer_bind[p]));
    memset(remote_slot[p], 0, sizeof(remote_slot[p]));
    if (!sl_zigbee_af_event_is_scheduled(&peer_age_event)) {
      sl_zigbee_af_event_set_delay_ms(&peer_age_event, PEER_AGE_CHECK_MS);
    }
  }
  peer_heard[p] = halCommonGetInt32uMillisecondTick();
  // Change-only: a value the program already has, with nothing newer waiting, is dropped.
  if (remote_slot[p][w].known && remote_slot[p][w].value == value) {
    remote_slot[p][w].dirty = false;  // back to what the program has: nothing to deliver
    return;
  }
  remote_slot[p][w].pending = value;
  remote_slot[p][w].dirty = true;
  if (!sl_zigbee_af_event_is_scheduled(&remote_event)) sl_zigbee_af_event_set_active(&remote_event);
}

// Size in bytes of the ZCL data types a program can receive as a number; 0 = not handled.
static uint8_t zcl_int_size(uint8_t type, bool *is_signed)
{
  *is_signed = false;
  switch (type) {
    case 0x10: case 0x18: case 0x20: case 0x30: return 1;   // bool, bitmap8, uint8, enum8
    case 0x19: case 0x21: case 0x31: return 2;              // bitmap16, uint16, enum16
    case 0x22: return 3;
    case 0x1B: case 0x23: return 4;
    case 0x28: *is_signed = true; return 1;
    case 0x29: *is_signed = true; return 2;
    case 0x2B: *is_signed = true; return 4;
    default:   return 0;
  }
}

void h2_rules_incoming(uint16_t source_node, uint8_t source_endpoint, uint16_t cluster,
                       const uint8_t *msg, uint16_t len)
{
  if (!active || watch_count == 0 || len < 3) return;
  uint8_t fc = msg[0];
  if ((fc & 0x03) != 0x00 || (fc & 0x04)) return;       // global, not manufacturer-specific
  uint8_t cmd = msg[2];
  if (cmd != 0x0A && cmd != 0x01) return;               // Report Attributes, Read Attributes Response
  if (source_node == sl_zigbee_af_get_node_id()) return;

  uint16_t off = 3;
  while (off + 3 <= len) {
    uint16_t attr = (uint16_t)(msg[off] | ((uint16_t)msg[off + 1] << 8));
    off += 2;
    if (cmd == 0x01) {                                  // read response carries a status first
      if (msg[off++] != 0x00) continue;                 // unsupported attribute: no type, no value
      if (off >= len) break;
    }
    bool is_signed;
    uint8_t size = zcl_int_size(msg[off++], &is_signed);
    if (size == 0 || off + size > len) break;           // a type we cannot step over: stop
    uint32_t raw = 0;
    for (uint8_t i = 0; i < size; i++) raw |= (uint32_t)msg[off + i] << (8 * i);
    off += size;
    if (is_signed && size < 4 && (raw & (1UL << (8 * size - 1)))) raw |= 0xFFFFFFFFUL << (8 * size);
    remote_value(source_node, source_endpoint, cmd == 0x01, cluster, attr, (int32_t)raw);
  }
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
  watch_count = 0;
  memset(peer_used, 0, sizeof(peer_used));
  memset(peer_bind, 0, sizeof(peer_bind));
  memset(timer_reaction, 0, sizeof(timer_reaction));
  found_mask = 0;
  memset(remote_slot, 0, sizeof(remote_slot));
  for (uint8_t b = 0; b < 8; b++) {
    h2_rules_host_max_clicks(b, 1, false);   // gesture settings belong to the program
  }
}

// ---------------------------------------------------------------------------
// Storage and upload
// ---------------------------------------------------------------------------

// An image is the instructions, optionally with a header and constant data (h2_bpf.h).
static bool image_valid(const uint8_t *buf, uint16_t len, uint32_t *bad_pc)
{
  h2_bpf_image_t image;
  if (bad_pc) *bad_pc = 0;
  if (!h2_bpf_parse(buf, len, &image)) return false;
  return h2_bpf_verify(image.code, image.code_len, image.data_len, bad_pc) == H2_BPF_OK;
}

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
      || !image_valid(code, hdr.length, NULL)) {
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
  if (!image_valid(staging, staging_len, &bad_pc)) {
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
  sl_zigbee_af_event_init(&remote_event, remote_handler);
  sl_zigbee_af_event_init(&bind_event, bind_handler);
  sl_zigbee_af_event_init(&peer_age_event, peer_age_handler);

  if (safe_mode) {
    safe = true;       // the stored program is neither loaded nor verified in safe mode
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
      if (safe) {                      // from the stored header only; nothing is loaded
        rules_header_t hdr;
        *value = (nvm3_readData(nvm3_defaultHandle, NVM3_KEY_RULES_HDR, &hdr, sizeof(hdr)) == ECODE_NVM3_OK)
                 ? (((uint32_t)hdr.crc << 16) | hdr.length) : 0;
        return true;
      }
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
    if ((zcl_type != 0x23 && zcl_type != 0x2B) || length < 4 || !active) return true;   // 32 bit, program running
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
