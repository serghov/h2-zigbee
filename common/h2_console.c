#include "h2_build.h"
#include "h2_console.h"

#if H2_BENCH

#include "app/framework/include/af.h"
#include "em_cmu.h"
#include "em_eusart.h"
#include "em_gpio.h"
#include "sl_iostream.h"
#include "sl_cli_instances.h"
#include "sl_cli_handles.h"
#include "sl_power_manager.h"

#define CON_TX_PORT   gpioPortB
#define CON_TX_PIN    0
#define CON_RX_PORT   gpioPortA
#define CON_RX_PIN    7
#define RX_RING       128           // power of two

static volatile uint8_t rx_ring[RX_RING];
static volatile uint8_t rx_head;    // written by the interrupt
static uint8_t rx_tail;

void EUSART0_RX_IRQHandler(void)
{
  while (EUSART0->STATUS & EUSART_STATUS_RXFL) {
    uint8_t b = (uint8_t)EUSART0->RXDATA;
    uint8_t next = (uint8_t)((rx_head + 1) & (RX_RING - 1));
    if (next != rx_tail) {
      rx_ring[rx_head] = b;
      rx_head = next;
    }
  }
  EUSART_IntClear(EUSART0, EUSART_IF_RXFL);
}

static sl_status_t con_write(void *context, const void *buffer, size_t length)
{
  (void)context;
  const uint8_t *p = (const uint8_t *)buffer;
  for (size_t i = 0; i < length; i++) {
    EUSART_Tx(EUSART0, p[i]);       // blocking, about 87 us per byte
  }
  return SL_STATUS_OK;
}

static sl_status_t con_read(void *context, void *buffer, size_t length, size_t *bytes_read)
{
  (void)context;
  uint8_t *p = (uint8_t *)buffer;
  size_t n = 0;
  while (n < length && rx_tail != rx_head) {
    p[n++] = rx_ring[rx_tail];
    rx_tail = (uint8_t)((rx_tail + 1) & (RX_RING - 1));
  }
  *bytes_read = n;
  return n ? SL_STATUS_OK : SL_STATUS_EMPTY;
}

static sl_iostream_t console_stream = {
  .write = con_write,
  .read  = con_read,
};

void h2_console_init(void)
{
  CMU_ClockEnable(cmuClock_GPIO, true);
  CMU_ClockEnable(cmuClock_EUSART0, true);

  GPIO_PinModeSet(CON_TX_PORT, CON_TX_PIN, gpioModePushPull, 1);
  GPIO_PinModeSet(CON_RX_PORT, CON_RX_PIN, gpioModeInputPull, 1);
  GPIO->EUSARTROUTE[0].TXROUTE = (CON_TX_PORT << _GPIO_EUSART_TXROUTE_PORT_SHIFT)
                               | (CON_TX_PIN << _GPIO_EUSART_TXROUTE_PIN_SHIFT);
  GPIO->EUSARTROUTE[0].RXROUTE = (CON_RX_PORT << _GPIO_EUSART_RXROUTE_PORT_SHIFT)
                               | (CON_RX_PIN << _GPIO_EUSART_RXROUTE_PIN_SHIFT);
  GPIO->EUSARTROUTE[0].ROUTEEN = GPIO_EUSART_ROUTEEN_TXPEN | GPIO_EUSART_ROUTEEN_RXPEN;

  EUSART_UartInit_TypeDef init = EUSART_UART_INIT_DEFAULT_HF;
  init.baudrate = 115200;
  EUSART_UartInitHf(EUSART0, &init);

  EUSART_IntClear(EUSART0, EUSART_IF_RXFL);
  EUSART_IntEnable(EUSART0, EUSART_IEN_RXFL);
  NVIC_ClearPendingIRQ(EUSART0_RX_IRQn);
  NVIC_EnableIRQ(EUSART0_RX_IRQn);

  // The high-frequency clock must stay on for the console to work.
  sl_power_manager_add_em_requirement(SL_POWER_MANAGER_EM1);

  sl_iostream_set_default(&console_stream);
  sl_cli_example_handle->iostream_handle = &console_stream;

  sl_zigbee_app_debug_println("");
  sl_zigbee_app_debug_println("H2 bench console ready");
}

#else  // !H2_BENCH

void h2_console_init(void)
{
}

#endif
