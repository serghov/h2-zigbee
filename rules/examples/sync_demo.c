// Demonstrates staying in sync with lamps that others also control.
//
// The lamps are in Zigbee group 1 and are bound to this switch, so they report their
// on/off state here. The switch keeps "any lamp on" in public variable 0, shows it on its
// LED (red = on), and a click turns the group off if anything is on, otherwise on.
// Switch a lamp from the hub and the LED and the next click follow.
#include "../h2_rules.h"

#define GROUP       1
#define ON_OFF      0x0006, 0x0000     // cluster, attribute
#define VAR_ANY_ON  0                  // public: 1 while at least one lamp is on
#define VAR_ON_MASK 1                  // private: bit n = lamp n is on

static inline void show(void)
{
  long any = var_get(VAR_ON_MASK) != 0;
  var_set(VAR_ANY_ON, any);            // reported to the hub when it changes
  if (any) led_set(0, 255, 0);
  else     led_release(0);
}

int on_event(struct h2_event *ev)
{
  if (ev->type == H2_EV_BOOT) {
    var_public(1 << VAR_ANY_ON);
    watch(ON_OFF);
    group_read(GROUP, ON_OFF);         // every lamp answers with its current state
    show();
    return 1;
  }
  if (ev->type == H2_EV_REPORT && H2_IS_REMOTE(ev->source)) {
    long bit = 1 << (ev->source - H2_SRC_REMOTE(0));
    long mask = var_get(VAR_ON_MASK);
    var_set(VAR_ON_MASK, ev->value ? (mask | bit) : (mask & ~bit));
    show();                            // news about the state: no commands from here
    return 1;
  }
  if (ev->source == H2_SRC_BUTTON(0) && ev->type == H2_EV_SINGLE) {
    zcl_group(GROUP, 0x0006, var_get(VAR_ANY_ON) ? 0x00 : 0x01, 0, 0);
    return 1;                          // the lamps' reports will update the state
  }
  return 0;
}
