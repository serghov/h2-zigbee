#ifndef H2_BUILD_H
#define H2_BUILD_H

// H2_BENCH selects a development build. It is OFF unless the build defines H2_BENCH=1
// (the CMake projects take it from the H2_BENCH environment variable).
//
// A bench build adds features that must never run on an installed switch:
//   - a serial console on two wall-connector lines (h2_console.c): log output on PB0
//     ("WALL5"), command input on PA7 ("WALL3"). On a real wall module PB0 is a line the
//     stock firmware drives for an unknown purpose and PA7 is driven by the wall module,
//     so this is only for a front plate powered on the low-voltage bench.
//   - the wall-UART tap, frame injection and the deliberate-hang attribute (h2_tap.c,
//     h2_opple.c)
//   - safe mode joining any open network when it has none (h2_safe.c)
//
// The watchdog, safe mode and the read-only boot diagnostics are part of every build.
#ifndef H2_BENCH
#define H2_BENCH 0
#endif

#endif // H2_BUILD_H
