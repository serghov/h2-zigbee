// Test program for the interpreter: functions that are really called (not inlined),
// recursion-free nesting, callee-saved values across calls, and constant tables.
#include "../rules/h2_rules.h"

#define NOINLINE static __attribute__((noinline))

struct mode { u8 level; u8 red; u8 blue; u8 scene; };
static const struct mode modes[3] = { { 10, 255, 0, 1 }, { 20, 0, 255, 2 }, { 30, 128, 128, 3 } };
static const char tag[] = "H2";

NOINLINE long add3(long a, long b, long c) { return a + b + c; }

NOINLINE long apply(long which)
{
  const struct mode *m = &modes[which];
  led_set(0, m->red, m->blue);
  scene_recall(1, m->scene);
  return m->level;
}

NOINLINE long nested(long which)
{
  long before = var_get(0);              // must survive the calls below
  long level = apply(which);
  return add3(before, level, tag[1]);    // tag[1] = '2' = 50
}

NOINLINE void fill(u8 *buf, long n)
{
  for (long i = 0; i < n; i++) buf[i] = (u8)(i + 1);
}

int on_event(struct h2_event *ev)
{
  if (ev->type == 1) return (int)nested(ev->value);          // table + nested calls
  if (ev->type == 2) {                                       // callee writes the caller's buffer
    u8 buf[4];
    fill(buf, 4);
    zcl_group(7, 6, buf[3], buf, 4);
    return buf[0] + buf[1] + buf[2] + buf[3];
  }
  return 0;
}
