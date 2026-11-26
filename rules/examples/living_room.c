// Living room: a 4-button switch for two sections of light.
//
//   Wired section, right column: two relays. Relay 1 only gives light while relay 2, the
//   master, is on (they are wired in series), so the section is off, half (master) or
//   full (both).
//   Smart section, left column: Zigbee group 17 = three bulbs and a plug with a lamp.
//   Half is the lamp plus the bulbs at 60 % warm, full is the bulbs at 100 % a bit cooler.
//
// Both sections work the same way, and neither affects the other:
//   top button     from off: half. Each further press switches between half and full,
//                  so a quick double press from off gives full. Buttons act as they go
//                  down.
//   bottom button  off
//   bottom LED     shows where to press to turn the section off, as on the other
//                  switches: dim and bluish in half, bright purple in full, dark when off
//
// The bulbs keep half and full as scenes 1 and 2 of the group, so a press is one message
// and each bulb changes brightness and colour in one step. The scenes have to be taught
// once, and again after a bulb is replaced or the values below change: hold the smart
// section's bottom button for 5 seconds. Its LED goes red, the lights step through half
// and full for about five seconds, and go off.
//
// The levels are public variables 0 (wired) and 1 (smart): 0 off, 1 half, 2 full. The hub
// can read them, and writing one sets that section. The smart level follows what the
// bulbs and the plug report, and the wired level follows the relays, whoever switches them.
//
// Needs firmware 0x88 or later (relay events).
#include "../lib/lights_tradfri.h"
#include "../lib/sync.h"
#include "../lib/scenes.h"
#include "../lib/each.h"
#include "../lib/reporting.h"

#ifndef GROUP
#define GROUP          17
#endif

// Buttons and LEDs share numbers: 0 upper left, 1 lower left, 2 upper right, 3 lower right.
#define SMART_TOP      0
#define SMART_BOTTOM   1
#define WIRED_TOP      2
#define WIRED_BOTTOM   3

#define MASTER         1                // relay 2: the first half of the wired section
#define SECOND         0                // relay 1: the other half, only lit with the master

static const struct { u8 level; u16 mireds; } SMART[] = {
  [1] = { PERCENT(60),  KELVIN(2200) },
  [2] = { PERCENT(100), KELVIN(2700) },
};
#define FULL_IF_BELOW  KELVIN(2450)     // a reported colour cooler than this counts as full

#define VAR_WIRED      0                // public
#define VAR_SMART      1                // public
#define VAR_ON_MASK    2                // one bit per bulb or plug that is on
#define VAR_MIREDS     3                // last colour temperature a bulb reported

// What these bulbs do with scene recalls (measured, RESEARCH.md 2026-11-24):
//  - Two different recalls arriving within about a tenth of a second (half then full, or
//    back) leave the brightness stuck somewhere between the two.
//  - A recall of the scene they should be in, any time later, puts that right.
// And what group messages do: each is put on the air several times over a second or so,
// by the switch and by every device that passes it on. A bulb that missed the first copy
// takes a later one, which by then can be older than the next press's message. Rapid
// presses then leave bulbs in different states, and repeating messages makes it worse.
// So a press goes to each lamp by itself: such a message is acknowledged, retried only if
// it was not, and cannot overtake a newer one. The last one is sent once more a second
// after the last press, which also repairs a brightness left stuck by a very fast double
// tap. Reports in that time are from our own commands and must not change the level.
// A level written by the hub goes to the group instead: the hub does not write in quick
// succession, and the allowance for hub-caused messages would not cover every lamp.
#define TIMER_SETTLE   2
#define SETTLE_MS      1000
#define VAR_SETTLING   5                // 2 after a command, 1 after its repeat, 0 settled

#define VAR_KNOWN      8                // one bit per lamp or plug that has been heard
#define VAR_BY_GROUP   9                // 1: the level in force came from the hub, send to the group

// Off from full: the second relay is switched off this long after the master.
#define TIMER_SECOND   0
#define SECOND_LATER_MS 300

// The hub puts the bulbs' colour reporting back to 30 s whenever it configures them, so the
// one-second setting is sent again once a day.
#define TIMER_HOURLY   3
#define HOUR_MS        3600000
#define VAR_HOURS      4

// Teaching the scenes: 0 not teaching, 1 the button is being held, 2.. the steps.
#define TIMER_TEACH    1
#define TEACH_HOLD_MS  5000
#define TEACH_STEP_MS  500
#define VAR_TEACH      6


// led_set(led, red, blue), each 0..255.
static const struct { u8 red, blue; } GLOW[] = {
  [0] = { 0,   0   },
  [1] = { 25,  70  },                   // half: dim, towards blue
  [2] = { 255, 255 },                   // full: bright purple
};

static __attribute__((noinline)) void glow(long lit_led, long dark_led, long level)
{
  led_set(lit_led, GLOW[level].red, GLOW[level].blue);
  led_set(dark_led, 0, 0);
}

// What a press does: the bottom button is off; the top one is half from off, and
// otherwise the other of half and full.
static __attribute__((noinline)) long after_press(long level, long top)
{
  if (!top) return 0;
  return level == 1 ? 2 : 1;
}

// ---- wired section -----------------------------------------------------------------------
static __attribute__((noinline)) void wired_show(long level)
{
  var_set(VAR_WIRED, level);
  glow(WIRED_BOTTOM, WIRED_TOP, level);
}

// The firmware leaves a relay alone that is already in the wanted state, and sends both
// relays to the wall module in one message.
static __attribute__((noinline)) void wired_set(long level)
{
  if (level < 0 || level > 2) level = 0;
  if (level == 0 && relay_get(SECOND)) {
    // Off from full: the wall module switches its relays one after the other, and the
    // master is the one that puts the light out. So the master goes alone, at once, and
    // the second relay follows a moment later, when nobody sees it.
    relay_set(MASTER, H2_OFF);
    timer_start(TIMER_SECOND, SECOND_LATER_MS);
  } else {
    relay_set(MASTER, level >= 1 ? H2_ON : H2_OFF);
    relay_set(SECOND, level >= 2 ? H2_ON : H2_OFF);
  }
  wired_show(level);
}

// Something else switched a relay (the hub, a script). The second relay alone lights
// nothing: if the master just went off it goes off too, and if it came on in the dark the
// master comes on with it.
static __attribute__((noinline)) void wired_follow(void)
{
  long master = relay_get(MASTER), second = relay_get(SECOND);
  if (second && !master) {
    if (var_get(VAR_WIRED)) { relay_set(SECOND, H2_OFF); second = 0; }
    else                    { relay_set(MASTER, H2_ON);  master = 1; }
  }
  wired_show(master ? (second ? 2 : 1) : 0);
}

// ---- smart section -----------------------------------------------------------------------
static __attribute__((noinline)) void smart_show(long level)
{
  var_set(VAR_SMART, level);
  glow(SMART_BOTTOM, SMART_TOP, level);
}

static __attribute__((noinline)) void smart_send(void)
{
  long level = var_get(VAR_SMART);
  long known = var_get(VAR_KNOWN);
  u8 p[3];
  p[0] = (u8)GROUP;
  p[1] = (u8)(GROUP >> 8);
  p[2] = (u8)level;                     // scene 1 = half, scene 2 = full
  // To each lamp heard so far; to the group only while none has been (just after start).
  long sent = 0;
  if (!var_get(VAR_BY_GROUP)) {
    sent = level ? each_send(known, CL_SCENES, CMD_SCENE_RECALL, p, 3)
                 : each_send(known, CL_ON_OFF, CMD_OFF, 0, 0);
  }
  if (!sent) {
    if (level) scene_recall(GROUP, level);
    else       lights_off(GROUP);
  }
}

static __attribute__((noinline)) void smart_set(long level)
{
  if (level < 0 || level > 2) level = 0;
  smart_show(level);                    // at once; the reports confirm it
  smart_send();
  if (!level) var_set(VAR_ON_MASK, 0);  // do not wait for a member that never reports "off"
  var_set(VAR_SETTLING, 2);
  timer_start(TIMER_SETTLE, SETTLE_MS);
}

// One step of teaching, half a second apart. For each scene: bring the lamps there, send
// the colour and the "on" a second time, then have them keep it, twice. Nothing else is
// sent in the same step as "keep": a plug that got the final "off" first kept that.
static __attribute__((noinline)) void teach_step(void)
{
  long step = var_get(VAR_TEACH);
  if (step == 1) {                      // held long enough: start
    var_set(VAR_SETTLING, 2);
    timer_stop(TIMER_SETTLE);
    led_set(SMART_BOTTOM, 255, 0);
    step = 2;
  }
  long part = (step - 2) & 3;           // steps 2..5 half, 6..9 full, 10 done
  long level = (step < 6) ? 1 : 2;
  if (step >= 10) {
    var_set(VAR_TEACH, 0);
    var_set(VAR_BY_GROUP, 0);
    smart_set(var_get(VAR_SMART));      // off: the hold that started this was an "off" press
    return;
  }
  if (part == 0) {
    lights_on(GROUP, SMART[level].level, SMART[level].mireds);
  } else if (part == 1) {
    lights_colour(GROUP, SMART[level].mireds);
    zcl_group(GROUP, CL_ON_OFF, CMD_ON, 0, 0);
  } else {
    scene_keep(GROUP, level);
  }
  var_set(VAR_TEACH, step + 1);
  timer_start(TIMER_TEACH, TEACH_STEP_MS);
}

int on_event(struct h2_event *ev)
{
  if (ev->type == H2_EV_BOOT) {
    var_public((1 << VAR_WIRED) | (1 << VAR_SMART));
    press_times(0, 100);               // hold time unchanged, double-click window 100 ms
    wired_follow();                    // start from what the relays are
    sync_start(GROUP, 1);
    // The bulbs should report a colour change within a second (the hub sets 30 s).
    report_within(GROUP, CL_COLOUR, ATTR_COLOUR_TEMP, 1, 900);
    smart_show(var_get(VAR_SMART));
    timer_start(TIMER_HOURLY, HOUR_MS);
    return 1;
  }
  if (ev->source == H2_SRC_TIMER && ev->value == TIMER_SECOND) {
    relay_set(SECOND, var_get(VAR_WIRED) >= 2 ? H2_ON : H2_OFF);   // whatever the level is by now
    return 1;
  }
  if (ev->source == H2_SRC_SYSTEM && ev->type == H2_EV_RELAY) {
    wired_follow();
    return 1;
  }
  if (ev->source == H2_SRC_TIMER && ev->value == TIMER_HOURLY) {
    // Ask the group for its state again: a lamp whose answer was lost at start, or that
    // was dropped after a silent hour, is found (and sent to by itself) from then on.
    group_read(GROUP, CL_ON_OFF, ATTR_ON_OFF);
    var_set(VAR_HOURS, var_get(VAR_HOURS) + 1);
    if (var_get(VAR_HOURS) >= 24) {
      report_within(GROUP, CL_COLOUR, ATTR_COLOUR_TEMP, 1, 900);
      var_set(VAR_HOURS, 0);
    }
    timer_start(TIMER_HOURLY, HOUR_MS);
    return 1;
  }
  if (ev->source == H2_SRC_TIMER && ev->value == TIMER_SETTLE) {
    long settling = var_get(VAR_SETTLING);
    if (settling == 2) {
      smart_send();
      timer_start(TIMER_SETTLE, SETTLE_MS);
    }
    var_set(VAR_SETTLING, settling > 0 ? settling - 1 : 0);
    return 1;
  }
  if (ev->source == H2_SRC_TIMER && ev->value == TIMER_TEACH) {
    teach_step();
    return 1;
  }
  // News from the bulbs and the plug: follow it, send nothing.
  long news = sync_report(ev, VAR_ON_MASK, VAR_MIREDS);
  each_track(ev, VAR_KNOWN);
  if (news == 3) return 1;
  if (news) {
    long level = var_get(VAR_SMART);
    long mireds = var_get(VAR_MIREDS);
    // From off, only something reported coming on raises the level: an "off" report while
    // others have yet to report theirs must not.
    long came_on = (news == 1 && ev->type == H2_EV_REPORT && ev->value);
    if (var_get(VAR_SETTLING))                      ;       // our own commands are still landing
    else if (!sync_any_on(VAR_ON_MASK))             smart_show(0);
    else if (level ? news == 2 : came_on)           smart_show((mireds && mireds < FULL_IF_BELOW) ? 2 : 1);
    return 1;
  }

  // The hub wrote a level.
  if (ev->source == H2_SRC_SYSTEM && ev->type == H2_EV_VAR) {
    long level = var_get(ev->value);
    if (level < 0 || level > 2) level = 0;
    if (ev->value == VAR_WIRED)      wired_set(level);
    else if (ev->value == VAR_SMART && var_get(VAR_TEACH) < 2) {   // not while teaching
      var_set(VAR_BY_GROUP, 1);
      smart_set(level);
    }
    return 1;
  }

  if (ev->source > H2_SRC_BUTTON(3)) return 0;
  long b = ev->source;
  if (var_get(VAR_TEACH) > 1) return 1;            // teaching: buttons wait
  if (b == SMART_BOTTOM && ev->type == H2_EV_HOLD_RELEASE && var_get(VAR_TEACH) == 1) {
    var_set(VAR_TEACH, 0);                         // let go before the 5 seconds
    timer_stop(TIMER_TEACH);
    return 1;
  }
  if (b == SMART_BOTTOM && ev->type == H2_EV_HOLD) {      // still down: perhaps the 5 s hold
    var_set(VAR_TEACH, 1);
    timer_start(TIMER_TEACH, TEACH_HOLD_MS);
    return 1;
  }
  // Act the moment a button goes down (PRESS), not when it comes up: waiting for the
  // release costs as long as the finger stays on the button. A second tap within 100 ms of
  // the first release is only reported when it is released (DOUBLE); it counts too.
  if (ev->type != H2_EV_PRESS && ev->type != H2_EV_DOUBLE) return 1;

  if (b == WIRED_TOP || b == WIRED_BOTTOM) {
    wired_set(after_press(var_get(VAR_WIRED), b == WIRED_TOP));
  } else {
    var_set(VAR_BY_GROUP, 0);
    smart_set(after_press(var_get(VAR_SMART), b == SMART_TOP));
  }
  return 1;
}
