// Example rules for the dimmer.
//   click         toggle the lamp output and recall scene 1 (on) or 2 (off) on group 1
//   double click  lamp output on and recall scene 3. Clicks are reported at once, so
//                 the first click of a double has already run the click rule.
//   5 s hold      blink the LED red/blue with a timer until released
#include "../h2_rules.h"

#define GROUP 1

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
      case H2_EV_DOUBLE:
        relay_set(0, H2_ON);
        scene_recall(GROUP, 3);
        return 1;
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
