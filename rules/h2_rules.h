// Header for H2 rule programs. Compile with:
//   clang -target bpf -mcpu=v4 -O2 -c rules.c -o rules.o        (or use rules/h2rules.py)
//
// A rule program is one function, on_event(), called for every event. Return 1 if the
// program handled the event (the firmware then skips its built-in behaviour for it), or 0
// to let the firmware do what it normally does.
//
// On the 2- and 4-button switch the firmware acts on a button the moment it goes down
// (relay or bound lights), before any click is known. To take a button over, return 1 for
// its PRESS event; the firmware then stays out of that whole gesture and only the program
// acts on SINGLE, DOUBLE, HOLD and HOLD_RELEASE. Buttons there are numbered
// gang * 2 + side (0 = up, 1 = down); a double click always follows a single click, and
// triple clicks and max_clicks() do not apply. See examples/switch_demo.c.
//
// Restrictions of the firmware's interpreter: no global variables, no string literals,
// no function calls other than the host functions below and static inline functions.
// Keep state with var_get()/var_set().
#ifndef H2_RULES_H
#define H2_RULES_H

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef int            s32;

// ---- events ---------------------------------------------------------------------------
struct h2_event {
  u8  source;      // H2_SRC_*
  u8  type;        // H2_EV_*
  s32 value;       // knob steps (signed), timer id, ...
  u32 millis;      // time since boot
  u16 cluster;     // H2_EV_REPORT: the cluster and attribute that was reported
  u16 attr;
};

#define H2_SRC_BUTTON(n)   (n)        // buttons 0..7 (the dimmer's knob button is 0)
#define H2_SRC_KNOB        16
#define H2_SRC_TIMER       32
#define H2_SRC_SYSTEM      48
#define H2_SRC_REMOTE(n)   (64 + (n)) // another device, n = 0..7 in order of first report
#define H2_IS_REMOTE(s)    ((s) >= 64 && (s) < 72)

#define H2_EV_PRESS         1         // went down
#define H2_EV_RELEASE       2         // came up
#define H2_EV_SINGLE        3         // one click
#define H2_EV_DOUBLE        4         // needs max_clicks(button, 2, ...) or more
#define H2_EV_TRIPLE        5         // needs max_clicks(button, 3, ...)
#define H2_EV_HOLD          6         // held past the hold threshold
#define H2_EV_HOLD_RELEASE  7         // released after a hold
#define H2_EV_ROTATE        8         // knob: value = steps, positive clockwise
#define H2_EV_TIMER         9         // value = timer id
#define H2_EV_BOOT         10         // once after start-up, and after a program is installed
#define H2_EV_ROTATE_PRESSED 11       // knob turned while pressed: value = steps
#define H2_EV_VAR          12         // source H2_SRC_SYSTEM: a public variable was written
                                      // from outside; value = its index (read it with var_get)
#define H2_EV_TRIGGER      13         // source H2_SRC_SYSTEM: a trigger arrived; value = its number
#define H2_EV_REPORT       14         // source H2_SRC_REMOTE(n): that device's attribute
                                      // ev->cluster / ev->attr now has the value ev->value

// ---- host functions ----------------------------------------------------------------------
#define H2_FN(id, ret, name, ...) static ret (*name)(__VA_ARGS__) = (void *)id

#define H2_OFF     0
#define H2_ON      1
#define H2_TOGGLE  2

// Public variables: the hub (or anything on the network) can read and write the variables
// a program declares public, each as attribute 0xFFA0 + index on the Aqara cluster. Call
// var_public() on H2_EV_BOOT. A write with a new value raises H2_EV_VAR; when the program
// itself changes a public variable, the switch reports it to the hub. Writing attribute
// 0xFFB0 raises H2_EV_TRIGGER. Radio messages sent while handling these two events come
// from a small allowance (about 4 per 10 s); use them to update state and LEDs, not to
// send commands.
// State of other devices. A lamp bound to this switch (its On/Off, Level or Colour
// cluster bound to the switch) reports its changes here; group_read() asks all members of
// a group for a value. Name the attributes of interest with watch() on H2_EV_BOOT (at
// most 4); each change then arrives as H2_EV_REPORT, only when the value differs from the
// last one delivered, and at most every 250 ms per device and attribute. Treat a report
// as news about the state: update variables and LEDs. Radio messages sent while handling
// one come from the same small allowance as for H2_EV_VAR.
H2_FN(15, long, watch,        long cluster, long attr);
H2_FN(16, long, group_read,   long group, long cluster, long attr);

H2_FN(14, long, var_public,   long mask);                              // bit n = variable n is public
H2_FN( 1, long, relay_set,    long gang, long mode);                  // H2_OFF / H2_ON / H2_TOGGLE
H2_FN( 2, long, relay_get,    long gang);                             // 1 if on
H2_FN( 3, long, level_set,    long gang, long level);                 // dimmer output level 1..254
H2_FN( 4, long, scene_recall, long group, long scene);                // Recall Scene to a group
H2_FN( 5, long, zcl_group,    long group, long cluster, long command, const void *payload, long len);
H2_FN( 6, long, led_set,      long led, long red, long blue);         // 0..255 each; LED becomes manual
H2_FN( 7, long, led_release,  long led);                              // back to the normal indicator
H2_FN( 8, long, var_get,      long index);                            // 16 variables, zero at boot
H2_FN( 9, long, var_set,      long index, long value);
H2_FN(10, long, timer_start,  long id, long milliseconds);            // H2_EV_TIMER later; restarts if running
H2_FN(11, long, timer_stop,   long id);
H2_FN(12, long, log_value,    long tag, long value);                  // debug print on the bench console
// Multi-click detection for a button; call it on H2_EV_BOOT. clicks = 1 (default), 2 or 3.
//   wait = H2_CLICKS_INSTANT  every click is reported at once: SINGLE, then DOUBLE for a
//                             second click within 300 ms, then TRIPLE. Nothing is delayed,
//                             but a DOUBLE always follows a SINGLE.
//   wait = H2_CLICKS_WAIT     one event per gesture, 300 ms after the last click. A DOUBLE
//                             arrives alone, but a SINGLE is delayed by 300 ms.
#define H2_CLICKS_INSTANT  0
#define H2_CLICKS_WAIT     1
H2_FN(13, long, max_clicks,   long button, long clicks, long wait);

int on_event(struct h2_event *ev);

#endif // H2_RULES_H
