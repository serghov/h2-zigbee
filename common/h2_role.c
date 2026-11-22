#include "app/framework/include/af.h"
#include "nvm3_default.h"
#include "sl_power_manager.h"

#include "h2_role.h"
#include "h2_safe.h"

#define NVM3_KEY_ROLE   0x0211   // 0x0210 is the safe-mode record

static uint8_t current_role = H2_ROLE_ROUTER;
static uint8_t pending_role;
static sl_zigbee_af_event_t role_reboot_event;

static uint8_t reboot_wait_ticks;
static sl_zigbee_af_event_t other_network_event;

// Waits for the leave to complete (or 5 s), then stores the new role and reboots.
static void role_reboot_handler(sl_zigbee_af_event_t *event)
{
  if (sl_zigbee_af_network_state() != SL_ZIGBEE_NO_NETWORK && ++reboot_wait_ticks < 20) {
    sl_zigbee_af_event_set_delay_ms(event, 250);
    return;
  }
  nvm3_writeData(nvm3_defaultHandle, NVM3_KEY_ROLE, &pending_role, sizeof(pending_role));
  h2_safe_mark_healthy();   // a role change is a deliberate reboot, not a crash
  halReboot();
}

// The network of the role we are NOT in must not stay joined: the same device cannot be on
// one PAN twice, and a leftover router network would keep the radio busy. Runs once,
// shortly after boot.
static void other_network_handler(sl_zigbee_af_event_t *event)
{
  (void)event;
  sl_zigbee_app_debug_println("Role: %s (network index %d)",
                               current_role == H2_ROLE_ROUTER ? "router" : "sleepy end device",
                               current_role);
  if (current_role == H2_ROLE_ROUTER) {
    // With a sleepy network configured, the framework may nap while unjoined. A router
    // must not.
    sl_power_manager_add_em_requirement(SL_POWER_MANAGER_EM1);
  }
  uint8_t other = (current_role == H2_ROLE_ROUTER) ? H2_ROLE_SLEEPY : H2_ROLE_ROUTER;
  if (sl_zigbee_af_push_network_index(other) != SL_STATUS_OK) {
    return;
  }
  if (sl_zigbee_af_network_state() != SL_ZIGBEE_NO_NETWORK) {
    sl_zigbee_app_debug_println("Role: leaving leftover network on index %d", other);
    sl_zigbee_leave_network(SL_ZIGBEE_LEAVE_NWK_WITH_NO_OPTION);
  }
  sl_zigbee_af_pop_network_index();
}

// The role has to be in place before the framework initialises its plugins: their timers
// and events are bound to a network index when they are created. So this runs from inside
// the framework's own start-up, right after it has set up its endpoint table and its
// network-index stack. The build wraps sl_zigbee_af_endpoint_configure() for that
// (linker option --wrap, see the CMake project).
void __real_sl_zigbee_af_endpoint_configure(void);

void __wrap_sl_zigbee_af_endpoint_configure(void)
{
  __real_sl_zigbee_af_endpoint_configure();

  uint8_t stored;
  if (nvm3_readData(nvm3_defaultHandle, NVM3_KEY_ROLE, &stored, sizeof(stored)) == ECODE_NVM3_OK
      && stored <= H2_ROLE_SLEEPY) {
    current_role = stored;
  }

  // Every endpoint belongs to the selected network; the other network is never used.
  for (uint8_t i = 0; i < sl_zigbee_af_endpoint_count(); i++) {
    sli_zigbee_af_endpoints[i].networkIndex = current_role;
  }
  // Make it the framework's current network for good: pushed once, never popped, so it is
  // what every later push/pop pair returns to.
  sl_zigbee_af_push_network_index(current_role);
}

void h2_role_init(void)
{
  // sl_zigbee_af_main_init_cb() runs BEFORE the framework start-up step that applies the
  // role, so nothing here may depend on current_role. The role-dependent part is done in
  // other_network_handler(), two seconds after boot.
  sl_zigbee_af_event_init(&role_reboot_event, role_reboot_handler);
  sl_zigbee_af_event_init(&other_network_event, other_network_handler);
  sl_zigbee_af_event_set_delay_ms(&other_network_event, 2000);
}

uint8_t h2_role_get(void)
{
  return current_role;
}

void h2_role_set(uint8_t role)
{
  if (role > H2_ROLE_SLEEPY || role == current_role) {
    return;
  }
  pending_role = role;
  if (sl_zigbee_af_network_state() != SL_ZIGBEE_NO_NETWORK) {
    sl_zigbee_leave_network(SL_ZIGBEE_LEAVE_NWK_WITH_NO_OPTION);
  }
  reboot_wait_ticks = 0;
  sl_zigbee_af_event_set_delay_ms(&role_reboot_event, 250);
}
