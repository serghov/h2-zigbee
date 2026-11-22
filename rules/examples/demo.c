// Example rules for the dimmer.
//   click         toggle the lamp output and recall scene 1 (on) or 2 (off) on group 1
//   double click  switch the group's lights between dim and full brightness, and show
//                 which on the LED (red = dim, blue = full). Clicks are reported at once,
//                 so the first click of a double has already toggled the lamp; the
//                 double-click rule toggles it back.
//   5 s hold      blink the LED red/blue with a timer until released
#include "../h2_rules.h"

#define GROUP 1

static inline void group_level(long level)
{
  u8 p[3];
  p[0] = (u8)level;          // level
  p[1] = 0;                  // transition time, tenths of a second (16 bit)
  p[2] = 0;
  zcl_group(GROUP, 0x0008, 0x04, p, 3);          // Level Control: Move to Level (with On/Off)
}

int on_event(struct h2_event *ev)
{
  if (ev->type == H2_EV_BOOT) {
    max_clicks(0, 2, H2_CLICKS_INSTANT);
    return 1;
  }
  if (ev->source == H2_SRC_BUTTON(0)) {
    switch (ev->type) {
      case H2_EV_SINGLE:
        relay_set(0, H2_TOGGLE);
        scene_recall(GROUP, relay_get(0) ? 1 : 2);
        return 1;
      case H2_EV_DOUBLE: {
        relay_set(0, H2_TOGGLE);                 // undo what the first click did
        long dim = var_get(0) ^ 1;
        var_set(0, dim);
        group_level(dim ? 25 : 254);
        led_set(0, dim ? 255 : 0, dim ? 0 : 255);
        return 1;
      }
      case H2_EV_HOLD:
        var_set(1, 0);
        timer_start(0, 300);
        return 1;
      case H2_EV_HOLD_RELEASE:
        timer_stop(0);
        led_release(0);
        return 1;
    }
  }
  if (ev->source == H2_SRC_TIMER && ev->value == 0) {
    long phase = var_get(1) ^ 1;
    var_set(1, phase);
    led_set(0, phase ? 255 : 0, phase ? 0 : 255);
    timer_start(0, 300);
    return 1;
  }
  return 0;
}
