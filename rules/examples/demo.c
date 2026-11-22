// Example rules for the dimmer: the knob button toggles the lamp and recalls a scene on
// group 1; a double click cycles three scenes; a hold starts a blinking LED that a timer
// keeps going until the button is released.
#include "../h2_rules.h"

#define GROUP 1

int on_event(struct h2_event *ev)
{
  if (ev->source == H2_SRC_BUTTON(0)) {
    switch (ev->type) {
      case H2_EV_SINGLE:
        relay_set(0, H2_TOGGLE);
        scene_recall(GROUP, relay_get(0) ? 1 : 2);
        led_set(0, 128, 128);                    // half red, half blue
        return 1;
      case H2_EV_DOUBLE: {
        long n = (var_get(0) + 1) % 3;
        var_set(0, n);
        scene_recall(GROUP, n + 1);
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
