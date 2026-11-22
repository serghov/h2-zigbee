// Rules for a 2-button switch that drives a room light on its relay and a Zigbee bulb
// (or several) in group 1.
//
//   upper button   toggles the relay; the bulb follows it (on with the relay, off with it)
//   lower button   bulb only: warm light, and on the next click off
//
// Both buttons are taken over (PRESS returns 1), so the firmware's own press behaviour
// is off for them.
#include "../h2_rules.h"

#define GROUP        1
#define UPPER        H2_SRC_BUTTON(0)
#define LOWER        H2_SRC_BUTTON(1)
#define WARM_MIREDS  454              // 2200 K, the warmest this bulb goes
#define VAR_WARM     0                // 1 while the lower button has the bulb in warm light

// On/Off cluster: command 0 = off, 1 = on. No payload.
static inline void bulb_on_off(long on)
{
  zcl_group(GROUP, 0x0006, on ? 0x01 : 0x00, 0, 0);
}

// Colour Control cluster, Move to Colour Temperature: mireds, then transition time in
// tenths of a second, both 16 bit, low byte first.
static inline void bulb_warm(void)
{
  u8 p[4];
  p[0] = (u8)(WARM_MIREDS & 0xFF);
  p[1] = (u8)(WARM_MIREDS >> 8);
  p[2] = 5;
  p[3] = 0;
  zcl_group(GROUP, 0x0300, 0x0A, p, 4);
}

int on_event(struct h2_event *ev)
{
  if (ev->source != UPPER && ev->source != LOWER) {
    return 0;
  }
  if (ev->type != H2_EV_SINGLE) {
    return 1;                         // ours, but only clicks do anything
  }

  if (ev->source == UPPER) {
    relay_set(0, H2_TOGGLE);
    bulb_on_off(relay_get(0));
    var_set(VAR_WARM, 0);
    return 1;
  }

  // Lower button
  if (var_get(VAR_WARM)) {
    bulb_on_off(0);
    var_set(VAR_WARM, 0);
  } else {
    bulb_on_off(1);
    bulb_warm();
    var_set(VAR_WARM, 1);
  }
  return 1;
}
