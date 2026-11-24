// Host-side tests for the eBPF interpreter (common/h2_bpf.c).
// build+run: tests/run_bpf_tests.sh
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../common/h2_bpf.h"

struct ev { uint8_t source, type; int32_t value; uint32_t millis; };

static int fails;
#define CHECK(c, ...) do { if (!(c)) { fails++; printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

// ---- mock host ------------------------------------------------------------------------
static char calls[1024];
static long vars[16];
static int relay;
static uint64_t helper(h2_bpf_vm_t *vm, uint32_t id, const uint64_t a[5], bool *ok)
{
  char b[96];
  switch (id) {
    case 1: if (a[1] == 2) relay ^= 1; else relay = (int)a[1];
            snprintf(b, sizeof b, "relay(%ld,%ld) ", (long)a[0], (long)a[1]); break;
    case 2: return (uint64_t)relay;
    case 4: snprintf(b, sizeof b, "scene(%ld,%ld) ", (long)a[0], (long)a[1]); break;
    case 5: if (a[4] > 64 || (a[4] && !h2_bpf_check_ptr(vm, a[3], (uint32_t)a[4], false))) { *ok = false; return 0; }
            snprintf(b, sizeof b, "zcl(%ld,%ld,%ld,len%ld) ", (long)a[0], (long)a[1], (long)a[2], (long)a[4]); break;
    case 6: snprintf(b, sizeof b, "led(%ld,%ld,%ld) ", (long)a[0], (long)a[1], (long)a[2]); break;
    case 7: snprintf(b, sizeof b, "ledrel(%ld) ", (long)a[0]); break;
    case 8: return a[0] < 16 ? (uint64_t)vars[a[0]] : 0;
    case 9: if (a[0] < 16) vars[a[0]] = (long)a[1]; return 0;
    case 10: snprintf(b, sizeof b, "tstart(%ld,%ld) ", (long)a[0], (long)a[1]); break;
    case 11: snprintf(b, sizeof b, "tstop(%ld) ", (long)a[0]); break;
    case 13: return 0;
    default: *ok = false; return 0;
  }
  strncat(calls, b, sizeof(calls) - strlen(calls) - 1);
  return 0;
}

static h2_bpf_status_t run(const uint8_t *code, uint32_t len, struct ev *e, uint64_t *res, h2_bpf_vm_t *vm)
{
  static h2_bpf_region_t reg[1];
  reg[0].base = (const uint8_t *)e; reg[0].len = sizeof(*e); reg[0].writable = false;
  memset(vm, 0, sizeof(*vm));
  vm->code = code; vm->code_len = len; vm->regions = reg; vm->region_count = 1;
  vm->helper = helper; vm->budget = 2000;
  calls[0] = 0;
  return h2_bpf_run(vm, (uint64_t)(uintptr_t)e, res);
}

// ---- tiny assembler for hand-written programs --------------------------------------------
#define I(op, dst, src, off, imm) (op), (uint8_t)((dst) | ((src) << 4)), (uint8_t)((off) & 0xFF), (uint8_t)(((off) >> 8) & 0xFF), \
  (uint8_t)((uint32_t)(imm)), (uint8_t)((uint32_t)(imm) >> 8), (uint8_t)((uint32_t)(imm) >> 16), (uint8_t)((uint32_t)(imm) >> 24)
#define EXIT          I(0x95, 0, 0, 0, 0)
#define MOV64I(d, v)  I(0xb7, d, 0, 0, v)

static void expect_verify(const char *name, const uint8_t *c, uint32_t len, h2_bpf_status_t want)
{
  uint32_t pc = 0;
  h2_bpf_status_t st = h2_bpf_verify(c, len, 0, &pc);
  CHECK(st == want, "verify %s: got %d want %d (pc %u)", name, st, want, pc);
}

// Run a whole image (optional header + code + constant data), as the firmware does.
static h2_bpf_status_t run_image(const uint8_t *img, uint32_t len, struct ev *e, uint64_t *res,
                                 h2_bpf_vm_t *vm, bool *accepted)
{
  static h2_bpf_region_t reg[1];
  h2_bpf_image_t im;
  *accepted = h2_bpf_parse(img, len, &im)
              && h2_bpf_verify(im.code, im.code_len, im.data_len, NULL) == H2_BPF_OK;
  if (!*accepted) return H2_BPF_ERR_BAD_PROGRAM;
  reg[0].base = (const uint8_t *)e; reg[0].len = sizeof(*e); reg[0].writable = false;
  memset(vm, 0, sizeof(*vm));
  vm->code = im.code; vm->code_len = im.code_len; vm->data = im.data; vm->data_len = im.data_len;
  vm->regions = reg; vm->region_count = 1; vm->helper = helper; vm->budget = 2000;
  calls[0] = 0;
  return h2_bpf_run(vm, (uint64_t)(uintptr_t)e, res);
}
#define HDR(insns, data) 0x00, 1, (uint8_t)(insns), (uint8_t)((insns) >> 8), (uint8_t)(data), (uint8_t)((data) >> 8), 0, 0
static void expect_image(const char *name, const uint8_t *img, uint32_t len, bool want_accept,
                         h2_bpf_status_t want, uint64_t want_r0)
{
  struct ev e = { 1, 2, -3, 1000 }; uint64_t r = 0; h2_bpf_vm_t vm; bool acc;
  h2_bpf_status_t st = run_image(img, len, &e, &r, &vm, &acc);
  CHECK(acc == want_accept, "image %s: accepted=%d want %d", name, acc, want_accept);
  if (acc && want_accept) {
    CHECK(st == want, "image %s: got %d want %d (pc %u)", name, st, want, vm.fault_pc);
    if (st == H2_BPF_OK && want == H2_BPF_OK) CHECK(r == want_r0, "image %s: r0=%llu want %llu", name, (unsigned long long)r, (unsigned long long)want_r0);
  }
}
static void expect_run(const char *name, const uint8_t *c, uint32_t len, h2_bpf_status_t want, uint64_t want_r0)
{
  struct ev e = { 1, 2, -3, 1000 }; uint64_t r = 0; h2_bpf_vm_t vm;
  expect_verify(name, c, len, H2_BPF_OK);
  h2_bpf_status_t st = run(c, len, &e, &r, &vm);
  CHECK(st == want, "run %s: got %d want %d (pc %u)", name, st, want, vm.fault_pc);
  if (st == H2_BPF_OK && want == H2_BPF_OK) CHECK(r == want_r0, "run %s: r0=%llu want %llu", name, (unsigned long long)r, (unsigned long long)want_r0);
}

static uint8_t *load(const char *path, uint32_t *len)
{
  FILE *f = fopen(path, "rb"); if (!f) { perror(path); exit(2); }
  uint8_t *b = malloc(65536); *len = (uint32_t)fread(b, 1, 65536, f); fclose(f); return b;
}

int main(int argc, char **argv)
{
  // ---- malformed programs must be rejected -----------------------------------------------
  { uint8_t c[] = { MOV64I(0, 1) };                          expect_verify("falls off end", c, sizeof c, H2_BPF_ERR_BAD_PROGRAM); }
  { uint8_t c[] = { I(0xff, 0, 0, 0, 0), EXIT };             expect_verify("unknown opcode", c, sizeof c, H2_BPF_ERR_BAD_PROGRAM); }
  { uint8_t c[] = { I(0x05, 0, 0, 5, 0), EXIT };             expect_verify("jump past end", c, sizeof c, H2_BPF_ERR_BAD_PROGRAM); }
  { uint8_t c[] = { I(0x05, 0, 0, -3, 0), EXIT };            expect_verify("jump before start", c, sizeof c, H2_BPF_ERR_BAD_PROGRAM); }
  { uint8_t c[] = { I(0xb7, 11, 0, 0, 0), EXIT };            expect_verify("register 11", c, sizeof c, H2_BPF_ERR_BAD_PROGRAM); }
  { uint8_t c[] = { I(0xb7, 10, 0, 0, 0), EXIT };            expect_verify("write frame pointer", c, sizeof c, H2_BPF_ERR_BAD_PROGRAM); }
  { uint8_t c[] = { I(0x18, 0, 0, 0, 1) };                   expect_verify("truncated lddw", c, sizeof c, H2_BPF_ERR_BAD_PROGRAM); }
  { uint8_t c[] = { I(0x05, 0, 0, 1, 0), I(0x18, 0, 0, 0, 1), I(0, 0, 0, 0, 0), EXIT };
                                                             expect_verify("jump into lddw", c, sizeof c, H2_BPF_ERR_BAD_PROGRAM); }
  { uint8_t c[] = { I(0x85, 0, 1, 0, 1), EXIT };             expect_verify("local call past end", c, sizeof c, H2_BPF_ERR_BAD_PROGRAM); }
  { uint8_t c[] = { I(0x85, 0, 1, 0, -5), EXIT };            expect_verify("local call before start", c, sizeof c, H2_BPF_ERR_BAD_PROGRAM); }
  { uint8_t c[] = { I(0x85, 0, 2, 0, 0), EXIT };             expect_verify("call with unknown source", c, sizeof c, H2_BPF_ERR_BAD_PROGRAM); }
  { uint8_t c[] = { I(0x85, 0, 1, 0, 2), EXIT, I(0x18, 0, 0, 0, 1), I(0, 0, 0, 0, 0), EXIT };
                                                             expect_verify("local call into lddw", c, sizeof c, H2_BPF_ERR_BAD_PROGRAM); }
  { uint8_t c[] = { I(0x18, 1, 2, 0, 0), I(0, 0, 0, 0, 0), EXIT };
                                                             expect_verify("data reference without data", c, sizeof c, H2_BPF_ERR_BAD_PROGRAM); }
  { uint8_t c[] = { I(0xdb, 1, 2, 0, 0), EXIT };             expect_verify("atomic op", c, sizeof c, H2_BPF_ERR_BAD_PROGRAM); }
  { uint8_t c[] = { EXIT, 0, 0, 0 };                         expect_verify("length not multiple of 8", c, sizeof c, H2_BPF_ERR_BAD_PROGRAM); }
  expect_verify("empty", (const uint8_t *)"", 0, H2_BPF_ERR_BAD_PROGRAM);

  // ---- run-time containment ------------------------------------------------------------------
  { uint8_t c[] = { I(0x05, 0, 0, -1, 0) };                  expect_run("infinite loop", c, sizeof c, H2_BPF_ERR_BUDGET, 0); }
  { uint8_t c[] = { MOV64I(1, 0), I(0x71, 0, 1, 0, 0), EXIT };            expect_run("null read", c, sizeof c, H2_BPF_ERR_MEMORY, 0); }
  { uint8_t c[] = { I(0x71, 0, 1, 12, 0), EXIT };            expect_run("read past ctx", c, sizeof c, H2_BPF_ERR_MEMORY, 0); }
  { uint8_t c[] = { I(0x61, 0, 1, 9, 0), EXIT };             expect_run("read straddling ctx end", c, sizeof c, H2_BPF_ERR_MEMORY, 0); }
  { uint8_t c[] = { I(0x72, 1, 0, 0, 7), MOV64I(0, 0), EXIT };            expect_run("write read-only ctx", c, sizeof c, H2_BPF_ERR_MEMORY, 0); }
  { uint8_t c[] = { I(0x72, 10, 0, 0, 7), MOV64I(0, 0), EXIT };           expect_run("write above stack", c, sizeof c, H2_BPF_ERR_MEMORY, 0); }
  { uint8_t c[] = { I(0x7a, 10, 0, -260, 7), MOV64I(0, 0), EXIT };        expect_run("write below stack", c, sizeof c, H2_BPF_ERR_MEMORY, 0); }
  { uint8_t c[] = { I(0x85, 0, 0, 0, 99), EXIT };            expect_run("unknown helper", c, sizeof c, H2_BPF_ERR_HELPER, 0); }
  { uint8_t c[] = { MOV64I(4, 1234), MOV64I(5, 8), I(0x85, 0, 0, 0, 5), EXIT };
                                                             expect_run("helper given wild pointer", c, sizeof c, H2_BPF_ERR_HELPER, 0); }

  // ---- semantics -----------------------------------------------------------------------------
  { uint8_t c[] = { I(0x7a, 10, 0, -8, 41), I(0x79, 0, 10, -8, 0), I(0x07, 0, 0, 0, 1), EXIT }; expect_run("stack rw", c, sizeof c, H2_BPF_OK, 42); }
  { uint8_t c[] = { I(0x71, 0, 1, 1, 0), EXIT };             expect_run("ctx byte", c, sizeof c, H2_BPF_OK, 2); }
  { uint8_t c[] = { I(0x61, 0, 1, 4, 0), I(0x67, 0, 0, 0, 32), I(0xc7, 0, 0, 0, 32), I(0x87, 0, 0, 0, 0), EXIT };
                                                             expect_run("signed ctx value", c, sizeof c, H2_BPF_OK, 3); }
  { uint8_t c[] = { MOV64I(0, 7), MOV64I(1, 0), I(0x3f, 0, 1, 0, 0), EXIT };  expect_run("div by zero", c, sizeof c, H2_BPF_OK, 0); }
  { uint8_t c[] = { MOV64I(0, 7), MOV64I(1, 0), I(0x9f, 0, 1, 0, 0), EXIT };  expect_run("mod by zero", c, sizeof c, H2_BPF_OK, 7); }
  { uint8_t c[] = { MOV64I(0, -1), I(0x04, 0, 0, 0, 2), EXIT };           expect_run("alu32 zero-extends", c, sizeof c, H2_BPF_OK, 1); }
  { uint8_t c[] = { I(0x18, 0, 0, 0, 0x89abcdef), I(0, 0, 0, 0, 0x01234567), EXIT };  expect_run("lddw", c, sizeof c, H2_BPF_OK, 0x0123456789abcdefULL); }
  { uint8_t c[] = { MOV64I(0, 0), MOV64I(1, 10), I(0x07, 0, 0, 0, 3), I(0x17, 1, 0, 0, 1), I(0x55, 1, 0, -3, 0), EXIT };
                                                             expect_run("counted loop", c, sizeof c, H2_BPF_OK, 30); }
  { uint8_t c[] = { MOV64I(0, 1), MOV64I(1, -1), I(0x65, 1, 0, 1, 0), MOV64I(0, 2), EXIT }; expect_run("signed compare", c, sizeof c, H2_BPF_OK, 2); }
  { uint8_t c[] = { MOV64I(0, 1), MOV64I(1, -1), I(0x25, 1, 0, 1, 0), MOV64I(0, 2), EXIT }; expect_run("unsigned compare", c, sizeof c, H2_BPF_OK, 1); }
  { uint8_t c[] = { MOV64I(0, -7), I(0x37, 0, 0, 1, 2), EXIT };           expect_run("signed div", c, sizeof c, H2_BPF_OK, (uint64_t)-3); }
  { uint8_t c[] = { MOV64I(0, -7), I(0x97, 0, 0, 1, 3), EXIT };           expect_run("signed mod", c, sizeof c, H2_BPF_OK, (uint64_t)-1); }
  { uint8_t c[] = { I(0x18, 0, 0, 0, 0), I(0, 0, 0, 0, 0x80000000), I(0x37, 0, 0, 1, -1), EXIT }; expect_run("INT64_MIN / -1", c, sizeof c, H2_BPF_OK, 0x8000000000000000ULL); }
  { uint8_t c[] = { MOV64I(1, 0x1f0), I(0xbf, 0, 1, 8, 0), EXIT };        expect_run("movsx8", c, sizeof c, H2_BPF_OK, (uint64_t)-16); }
  { uint8_t c[] = { I(0x81, 0, 1, 4, 0), EXIT };                          expect_run("sign-extending load", c, sizeof c, H2_BPF_OK, (uint64_t)-3); }
  { uint8_t c[] = { MOV64I(0, 5), I(0x06, 0, 0, 0, 1), MOV64I(0, 6), EXIT }; expect_run("gotol", c, sizeof c, H2_BPF_OK, 5); }
  { uint8_t c[] = { MOV64I(0, 0x1234), I(0xd7, 0, 0, 0, 16), EXIT };      expect_run("bswap16 v4", c, sizeof c, H2_BPF_OK, 0x3412); }
  { uint8_t c[] = { MOV64I(0, 0x1234), I(0xdc, 0, 0, 0, 16), EXIT };      expect_run("bswap16", c, sizeof c, H2_BPF_OK, 0x3412); }

  // ---- calls between program functions ----------------------------------------------------
  { uint8_t c[] = { I(0x85, 0, 1, 0, 1), EXIT, MOV64I(0, 7), EXIT };
                                                             expect_run("local call returns", c, sizeof c, H2_BPF_OK, 7); }
  { uint8_t c[] = { MOV64I(6, 5), I(0x85, 0, 1, 0, 2), I(0xbf, 0, 6, 0, 0), EXIT, MOV64I(6, 9), MOV64I(0, 1), EXIT };
                                                             expect_run("callee-saved register restored", c, sizeof c, H2_BPF_OK, 5); }
  { uint8_t c[] = { I(0x7a, 10, 0, -8, 41), I(0x85, 0, 1, 0, 2), I(0x79, 0, 10, -8, 0), EXIT,
                    I(0x7a, 10, 0, -8, 99), MOV64I(0, 0), EXIT };
                                                             expect_run("each call has its own stack slice", c, sizeof c, H2_BPF_OK, 41); }
  { uint8_t c[] = { I(0xbf, 1, 10, 0, 0), I(0x07, 1, 0, 0, -8), I(0x85, 0, 1, 0, 2), I(0x79, 0, 10, -8, 0), EXIT,
                    I(0x7a, 1, 0, 0, 77), MOV64I(0, 0), EXIT };
                                                             expect_run("callee writes caller's buffer", c, sizeof c, H2_BPF_OK, 77); }
  { uint8_t c[] = { I(0x85, 0, 1, 0, 1), EXIT, I(0x7a, 10, 0, -136, 1), MOV64I(0, 0), EXIT };
                                                             expect_run("callee below its slice", c, sizeof c, H2_BPF_ERR_MEMORY, 0); }
  { uint8_t c[] = { I(0x7a, 10, 0, -136, 1), MOV64I(0, 0), EXIT };
                                                             expect_run("main below its slice", c, sizeof c, H2_BPF_ERR_MEMORY, 0); }
  { uint8_t c[] = { I(0x85, 0, 1, 0, -1), EXIT };            expect_run("unbounded recursion", c, sizeof c, H2_BPF_ERR_DEPTH, 0); }
  { uint8_t c[] = { MOV64I(1, 3), I(0x85, 0, 1, 0, 1), EXIT,                       // f(n): n ? n + f(n-1) : 0, depth 4
                    I(0x15, 1, 0, 5, 0), I(0xbf, 6, 1, 0, 0), I(0x07, 1, 0, 0, -1), I(0x85, 0, 1, 0, -4),
                    I(0x0f, 0, 6, 0, 0), EXIT, MOV64I(0, 0), EXIT };
                                                             expect_run("recursion within the depth limit", c, sizeof c, H2_BPF_OK, 6); }
  { uint8_t c[] = { I(0x85, 0, 1, 0, 2), I(0xbf, 0, 1, 0, 0), EXIT, MOV64I(1, 55), MOV64I(0, 0), EXIT };
                                                             expect_run("argument registers cleared on return", c, sizeof c, H2_BPF_OK, 0); }

  // ---- images with constant data -------------------------------------------------------------
  { uint8_t c[] = { HDR(4, 8), I(0x18, 1, 2, 0, 0), I(0, 0, 0, 0, 0), I(0x71, 0, 1, 1, 0), EXIT, 10, 20, 30, 40, 50, 60, 70, 80 };
                                                             expect_image("read constant data", c, sizeof c, true, H2_BPF_OK, 20); }
  { uint8_t c[] = { HDR(4, 8), I(0x18, 1, 2, 0, 4), I(0, 0, 0, 0, 0), I(0x61, 0, 1, 0, 0), EXIT, 10, 20, 30, 40, 1, 0, 0, 0 };
                                                             expect_image("constant data at an offset", c, sizeof c, true, H2_BPF_OK, 1); }
  { uint8_t c[] = { HDR(5, 8), I(0x18, 1, 2, 0, 0), I(0, 0, 0, 0, 0), I(0x72, 1, 0, 0, 9), MOV64I(0, 0), EXIT, 1, 2, 3, 4, 5, 6, 7, 8 };
                                                             expect_image("write to constant data", c, sizeof c, true, H2_BPF_ERR_MEMORY, 0); }
  { uint8_t c[] = { HDR(4, 8), I(0x18, 1, 2, 0, 4), I(0, 0, 0, 0, 0), I(0x79, 0, 1, 0, 0), EXIT, 1, 2, 3, 4, 5, 6, 7, 8 };
                                                             expect_image("read past the constant data", c, sizeof c, true, H2_BPF_ERR_MEMORY, 0); }
  { uint8_t c[] = { HDR(3, 8), I(0x18, 1, 2, 0, 8), I(0, 0, 0, 0, 0), EXIT, 1, 2, 3, 4, 5, 6, 7, 8 };
                                                             expect_image("data reference past the end", c, sizeof c, false, 0, 0); }
  { uint8_t c[] = { HDR(3, 8), I(0x18, 1, 2, 0, 0), I(0, 0, 0, 0, 1), EXIT, 1, 2, 3, 4, 5, 6, 7, 8 };
                                                             expect_image("data reference with high bits", c, sizeof c, false, 0, 0); }
  { uint8_t c[] = { HDR(2, 8), MOV64I(0, 1), EXIT, 1, 2, 3, 4 };                    expect_image("header longer than the image", c, sizeof c, false, 0, 0); }
  { uint8_t c[] = { HDR(1, 0), MOV64I(0, 1), EXIT };                               expect_image("header shorter than the image", c, sizeof c, false, 0, 0); }
  { uint8_t c[] = { 0x00, 2, 2, 0, 0, 0, 0, 0, MOV64I(0, 1), EXIT };               expect_image("unknown image version", c, sizeof c, false, 0, 0); }
  { uint8_t c[] = { HDR(0, 0) };                                                   expect_image("header with no code", c, sizeof c, false, 0, 0); }
  { uint8_t c[] = { HDR(2, 0), MOV64I(0, 3), EXIT };                               expect_image("header, no data", c, sizeof c, true, H2_BPF_OK, 3); }

  // ---- a real compiled rule program ----------------------------------------------------------
  if (argc > 1) {
    uint32_t len; uint8_t *code = load(argv[1], &len);
    expect_verify("demo", code, len, H2_BPF_OK);
    h2_bpf_vm_t vm; uint64_t r; struct ev e;
    #define EV(s, t, v) e = (struct ev){ s, t, v, 0 }; CHECK(run(code, len, &e, &r, &vm) == H2_BPF_OK, "demo run failed pc %u", vm.fault_pc)
    relay = 0; memset(vars, 0, sizeof vars);
    EV(48, 10, 0); CHECK(r == 1, "boot");
    EV(0, 3, 0); CHECK(r == 1 && !strcmp(calls, "relay(0,2) scene(1,1) "), "single#1: %s", calls);
    EV(0, 3, 0); CHECK(r == 1 && !strcmp(calls, "relay(0,2) scene(1,2) "), "single#2: %s", calls);
    EV(0, 4, 0); CHECK(!strcmp(calls, "relay(0,1) scene(1,3) "), "double#1: %s", calls);
    EV(0, 4, 0); CHECK(!strcmp(calls, "relay(0,1) scene(1,3) "), "double#2: %s", calls);
    EV(0, 6, 0); CHECK(!strcmp(calls, "tstart(0,300) "), "hold: %s", calls);
    EV(32, 9, 0); CHECK(!strcmp(calls, "led(0,255,0) tstart(0,300) "), "timer#1: %s", calls);
    EV(32, 9, 0); CHECK(!strcmp(calls, "led(0,0,255) tstart(0,300) "), "timer#2: %s", calls);
    EV(0, 7, 0); CHECK(!strcmp(calls, "tstop(0) ledrel(0) "), "hold release: %s", calls);
    EV(16, 8, 2); CHECK(r == 0 && calls[0] == 0, "rotate should be unhandled: %s", calls);
    printf("demo program: %u instructions, last run executed %u\n", len / 8, vm.executed);

    // ---- a compiled program with real calls and constant tables --------------------------------
    uint32_t clen = 0; uint8_t *cimg = NULL;
    if (argc > 2) {
      cimg = load(argv[2], &clen);
      bool acc; h2_bpf_image_t im;
      CHECK(h2_bpf_parse(cimg, clen, &im) && im.data_len > 0, "calls image should carry constant data");
      unsigned local = 0;
      for (uint32_t q = 0; q < im.code_len; q += 8) if (im.code[q] == 0x85 && (im.code[q + 1] >> 4) == 1) local++;
      CHECK(local >= 4, "calls image should contain calls between functions, found %u", local);
      #define EVI(s, t, v) e = (struct ev){ s, t, v, 0 }; CHECK(run_image(cimg, clen, &e, &r, &vm, &acc) == H2_BPF_OK && acc, "calls run failed pc %u", vm.fault_pc)
      memset(vars, 0, sizeof vars); vars[0] = 1000;
      EVI(0, 1, 0); CHECK(r == 1000 + 10 + 50 && !strcmp(calls, "led(0,255,0) scene(1,1) "), "calls mode 0: r=%ld %s", (long)r, calls);
      EVI(0, 1, 2); CHECK(r == 1000 + 30 + 50 && !strcmp(calls, "led(0,128,128) scene(1,3) "), "calls mode 2: r=%ld %s", (long)r, calls);
      EVI(0, 2, 0); CHECK(r == 10 && !strcmp(calls, "zcl(7,6,4,len4) "), "calls buffer: r=%ld %s", (long)r, calls);
      printf("calls program: %u instructions, %u bytes of data, %u calls between functions\n", im.code_len / 8, im.data_len, local);
    }

    // ---- fuzz: mutated real programs and random ones must never escape -----------------------
    // H2_FUZZ_SEED and H2_FUZZ_COUNT in the environment select other runs.
    unsigned seed = getenv("H2_FUZZ_SEED") ? (unsigned)strtoul(getenv("H2_FUZZ_SEED"), NULL, 0) : 1;
    srand(seed);
    unsigned accepted = 0, total = getenv("H2_FUZZ_COUNT") ? (unsigned)strtoul(getenv("H2_FUZZ_COUNT"), NULL, 0) : 600000;
    uint8_t *m = malloc(len);
    for (unsigned i = 0; i < total; i++) {
      uint32_t l = len;
      if (cimg && i % 3 == 2) {                        // mutated image with header, calls and data
        static uint8_t mi[8192];
        memcpy(mi, cimg, clen); int k = 1 + rand() % 4; while (k--) mi[rand() % clen] = (uint8_t)rand();
        bool acc; e = (struct ev){ (uint8_t)rand(), (uint8_t)(rand() % 4), rand() % 4, (uint32_t)rand() };
        run_image(mi, clen, &e, &r, &vm, &acc);
        if (acc) accepted++;
        continue;
      }
      if (i & 1) { memcpy(m, code, len); int k = 1 + rand() % 4; while (k--) m[rand() % len] = (uint8_t)rand(); }
      else {
        l = 8 * (1 + rand() % 12);
        static const uint8_t ops[] = { 0x07,0x0f,0x17,0x27,0x37,0x47,0x57,0x67,0x77,0x87,0x97,0xa7,0xb7,0xbf,0xc7,0x04,0x0c,0xb4,0xbc,
          0x61,0x69,0x71,0x79,0x81,0x89,0x91,0x06,0xd7,0x62,0x6a,0x72,0x7a,0x63,0x6b,0x73,0x7b,0x05,0x15,0x1d,0x25,0x55,0x65,0xa5,0x16,0x56,0x85,0x95,0x18,0xdc,0xd4 };
        for (uint32_t q = 0; q < l; q += 8) {
          m[q] = ops[rand() % sizeof ops]; m[q+1] = (uint8_t)((rand() % 11) | ((rand() % 11) << 4));
          int16_t off = (int16_t)(rand() % 3 ? (rand() % 25) - 12 : rand()); if (rand() % 8 == 0) off = (int16_t[]){ 1, 8, 16, 32 }[rand() % 4]; m[q+2] = (uint8_t)off; m[q+3] = (uint8_t)(off >> 8);
          int32_t imm = rand() % 3 ? (rand() % 70) - 4 : (int32_t)((unsigned)rand() * 2654435761u); memcpy(m + q + 4, &imm, 4);
        }
        memcpy(m + l - 8, (uint8_t[]){ EXIT }, 8);
      }
      // Random programs also run as an image with a little constant data behind them.
      static uint8_t wrapped[8 + 8 * 12 + 16];
      uint32_t dl = (i & 2) ? 8 * (1 + rand() % 2) : 0;
      if (!(i & 1) && dl) {
        uint8_t h[8] = { HDR(l / 8, dl) };
        memcpy(wrapped, h, 8); memcpy(wrapped + 8, m, l);
        for (uint32_t q = 0; q < dl; q++) wrapped[8 + l + q] = (uint8_t)rand();
        bool acc; e = (struct ev){ (uint8_t)rand(), (uint8_t)rand(), rand(), (uint32_t)rand() };
        run_image(wrapped, 8 + l + dl, &e, &r, &vm, &acc);
        if (acc) accepted++;
        continue;
      }
      if (h2_bpf_verify(m, l, 0, NULL) != H2_BPF_OK) continue;
      accepted++;
      e = (struct ev){ (uint8_t)rand(), (uint8_t)rand(), rand(), (uint32_t)rand() };
      run(m, l, &e, &r, &vm);                          // any status is fine; ASan/UBSan catch escapes
    }
    printf("fuzz (seed %u): %u programs, %u passed verification and were run\n", seed, total, accepted);
    free(m); free(code); free(cimg);
  }
  printf(fails ? "%d FAILURES\n" : "all tests passed\n", fails);
  return fails != 0;
}
