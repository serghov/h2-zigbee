// Sending a command to lamps one by one instead of to their group.
//
// A group message is a broadcast: nobody acknowledges it, and copies of it stay on the
// air for a second or so, so on quick presses a lamp can take an old copy after a newer
// command (RESEARCH.md, 2026-11-24). A message to one device is acknowledged, retried only
// if it was not, and cannot overtake a newer one.
//
// The program keeps, in a variable of its choice, one bit per device it has heard from
// (devices are numbered 0..7 in the order they were first heard: H2_SRC_REMOTE(n)).
#ifndef H2_LIB_EACH_H
#define H2_LIB_EACH_H

#include "../h2_rules.h"

// Call for every event: records devices as they appear and forgets them when they are lost.
static __attribute__((noinline)) void each_track(struct h2_event *ev, long var_mask)
{
  if (!H2_IS_REMOTE(ev->source)) return;
  long bit = 1 << (ev->source - H2_SRC_REMOTE(0));
  long mask = var_get(var_mask);
  var_set(var_mask, ev->type == H2_EV_LOST ? (mask & ~bit) : (mask | bit));
}

// Send a cluster command to every device in the mask. Returns how many it was handed over
// for (a message refused by a limit does not count), so the caller can fall back to the
// group while nobody has been heard yet.
static __attribute__((noinline)) long each_send(long mask, long cluster, long command,
                                                const void *payload, long len)
{
  long sent = 0;
  for (long n = 0; n < 8; n++) {
    if (!(mask & (1 << n))) continue;
    if (zcl_send(H2_TO_DEVICE(n), cluster, command, payload, len) == 0) sent++;
  }
  return sent;
}

#endif
