#ifndef H2_CONSOLE_H
#define H2_CONSOLE_H

// Bench console (H2_BENCH builds only): 115200 8N1 on EUSART0, TX = PB0, RX = PA7.
// Becomes the default output stream, so the firmware's debug prints appear on it, and the
// command-line interface reads from it. A no-op in release builds.
void h2_console_init(void);

#endif // H2_CONSOLE_H
