// Demonstrates public variables and triggers (dimmer or switch).
//
//   variable 0 "mode"   public. 0 = LED automatic, 1 = LED red, 2 = LED blue.
//                       Set it from the hub, or click the button to step through it.
//   trigger n           flashes the LED purple and counts in variable 1 (public, read it
//                       from the hub).
#include "../h2_rules.h"

#define VAR_MODE      0
#define VAR_TRIGGERS  1

H2_INLINE void show(long mode)
{
  if (mode == 1)      led_set(0, 255, 0);
  else if (mode == 2) led_set(0, 0, 255);
  else                led_release(0);
}

int on_event(struct h2_event *ev)
{
  if (ev->type == H2_EV_BOOT) {
    var_public((1 << VAR_MODE) | (1 << VAR_TRIGGERS));
    show(var_get(VAR_MODE));
    return 1;
  }
  if (ev->source == H2_SRC_SYSTEM && ev->type == H2_EV_VAR) {
    if (ev->value == VAR_MODE) show(var_get(VAR_MODE));      // the hub changed the mode
    return 1;
  }
  if (ev->source == H2_SRC_SYSTEM && ev->type == H2_EV_TRIGGER) {
    var_set(VAR_TRIGGERS, var_get(VAR_TRIGGERS) + 1);
    led_set(0, 255, 255);
    timer_start(0, 400);
    return 1;
  }
  if (ev->source == H2_SRC_TIMER && ev->value == 0) {
    show(var_get(VAR_MODE));
    return 1;
  }
  if (ev->source == H2_SRC_BUTTON(0) && ev->type == H2_EV_SINGLE) {
    long mode = (var_get(VAR_MODE) + 1) % 3;
    var_set(VAR_MODE, mode);                                 // reported to the hub
    show(mode);
    return 1;
  }
  return 0;
}
