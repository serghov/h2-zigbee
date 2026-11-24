// Structured fuzzer with an independent check, for common/h2_bpf.c.
//
// The address sanitizer cannot see the escapes that matter most here: the program's stack
// is a member of the VM structure, and the constant data sits in the same buffer as the
// code, so an access just outside either still lands in valid host memory. This harness
// therefore routes every load and store of the interpreter (built with
// -Dmemcpy=h2_traced_memcpy) and every pointer a helper accepts through its own model of
// what the program may touch, and generates structured programs (several functions,
// calls, stack and data accesses at the boundaries) rather than random bytes.
// Written by the reviewer of the calls/constant-data change (2026-11-24) and adopted.
// Builds hosted (with sanitizers) and freestanding 32-bit x86 (-DFREESTANDING -m32 -nostdlib).
// usage: bpf_oracle_fuzz [count] [seed]
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "h2_bpf.h"

#ifdef FREESTANDING
static long sys3(long n, long a, long b, long c) { long r; __asm__ volatile("int $0x80" : "=a"(r) : "a"(n), "b"(a), "c"(b), "d"(c) : "memory"); return r; }
static void out(const char *s) { size_t n = 0; while (s[n]) n++; sys3(4, 1, (long)s, (long)n); }
static void die(int c) { sys3(1, c, 0, 0); for (;;) {} }
#undef memcpy
void *memcpy(void *d, const void *s, size_t n) { uint8_t *a = d; const uint8_t *b = s; while (n--) *a++ = *b++; return d; }
void *memset(void *d, int c, size_t n) { uint8_t *a = d; while (n--) *a++ = (uint8_t)c; return d; }
static uint64_t udm(uint64_t a, uint64_t b, uint64_t *rem) { uint64_t q = 0, r = 0; for (int i = 63; i >= 0; i--) { r = (r << 1) | ((a >> i) & 1); if (r >= b) { r -= b; q |= 1ULL << i; } } if (rem) *rem = r; return q; }
uint64_t __udivdi3(uint64_t a, uint64_t b) { return udm(a, b, 0); }
uint64_t __umoddi3(uint64_t a, uint64_t b) { uint64_t r; udm(a, b, &r); return r; }
int64_t __divdi3(int64_t a, int64_t b) { int neg = (a < 0) ^ (b < 0); uint64_t q = udm(a < 0 ? 0 - (uint64_t)a : (uint64_t)a, b < 0 ? 0 - (uint64_t)b : (uint64_t)b, 0); return neg ? (int64_t)(0 - q) : (int64_t)q; }
int64_t __moddi3(int64_t a, int64_t b) { uint64_t r; udm(a < 0 ? 0 - (uint64_t)a : (uint64_t)a, b < 0 ? 0 - (uint64_t)b : (uint64_t)b, &r); return a < 0 ? (int64_t)(0 - r) : (int64_t)r; }
#else
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void out(const char *s) { fputs(s, stdout); fflush(stdout); }
static void die(int c) { exit(c); }
#endif
static void outn(uint64_t v) { char b[24]; int i = 23; b[i] = 0; do { b[--i] = (char)('0' + v % 10); v /= 10; } while (v); out(b + i); }
static void outx(uint64_t v) { char b[20]; int i = 19; b[i] = 0; do { b[--i] = "0123456789abcdef"[v & 15]; v >>= 4; } while (v); out("0x"); out(b + i); }

static uint64_t rs = 88172645463325252ULL;
static uint32_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return (uint32_t)(rs >> 16); }
#define R(n) (rnd() % (uint32_t)(n))

// ---- oracle ------------------------------------------------------------------------------
static h2_bpf_vm_t vm;
static struct { uint8_t source, type; int32_t value; uint32_t millis; uint16_t cluster, attr; } ctx;
static uint8_t imgbuf[4096 + 64];
static uint8_t *img = imgbuf + 32;         // guard bytes around the image
static const uint8_t *g_data; static uint32_t g_dlen;
static unsigned violations, acc_at_depth[8], data_reads, ctx_reads;
static const uint8_t *cur_img; static uint32_t cur_len;

static void dump(void) { out("  image:"); for (uint32_t i = 0; i < cur_len; i++) { if (i % 8 == 0) out("\n   "); out(" "); char h[3] = { "0123456789abcdef"[cur_img[i] >> 4], "0123456789abcdef"[cur_img[i] & 15], 0 }; out(h); } out("\n"); }
static void violation(const char *what, uint64_t a, uint64_t n) { violations++; out("VIOLATION: "); out(what); out(" addr "); outx(a); out(" len "); outn(n); out(" stack "); outx((uintptr_t)vm.stack); out(" low+"); outn((uint64_t)(vm.stack_low - vm.stack)); out("\n"); dump(); if (violations > 5) die(1); }

static int inside(uint64_t a, uint64_t n, uint64_t base, uint64_t len) { return n > 0 && a >= base && a - base <= len && n <= len - (a - base); }
static void low_invariant(void)
{
  ptrdiff_t d = vm.stack_low - vm.stack;
  if (d < 0 || d > H2_BPF_STACK_SIZE - H2_BPF_FRAME_SIZE || d % H2_BPF_FRAME_SIZE) violation("stack_low invariant", (uint64_t)d, 0);
}
static int readable(uint64_t a, uint64_t n)
{
  if (inside(a, n, (uintptr_t)vm.stack_low, (uint64_t)(vm.stack + H2_BPF_STACK_SIZE - vm.stack_low))) { acc_at_depth[5 - (vm.stack_low - vm.stack) / H2_BPF_FRAME_SIZE]++; return 1; }
  if (g_data && inside(a, n, (uintptr_t)g_data, g_dlen)) { data_reads++; return 1; }
  if (inside(a, n, (uintptr_t)&ctx, sizeof ctx)) { ctx_reads++; return 1; }
  return 0;
}
static int writable(uint64_t a, uint64_t n) { return inside(a, n, (uintptr_t)vm.stack_low, (uint64_t)(vm.stack + H2_BPF_STACK_SIZE - vm.stack_low)); }

// every load/store of the interpreter goes through here (-Dmemcpy=h2_traced_memcpy)
void *h2_traced_memcpy(void *d, const void *s, size_t n)
{
  low_invariant();
  if (!writable((uintptr_t)d, n) && !readable((uintptr_t)s, n)) violation("interpreter access", (uintptr_t)d, n), violation("  (src)", (uintptr_t)s, n);
  uint8_t *a = d; const uint8_t *b = s; while (n--) *a++ = *b++; return d;
}

static unsigned helper_ptr_ok, helper_calls;
static uint64_t helper(h2_bpf_vm_t *m, uint32_t id, const uint64_t a[5], bool *ok)
{
  helper_calls++; low_invariant();
  switch (id) {
    case 5: {                                   // exactly the firmware's zcl_group/zcl_send pattern
      if (a[4] > 64 || (a[4] > 0 && !h2_bpf_check_ptr(m, a[3], (uint32_t)a[4], false))) { *ok = false; return 0; }
      uint8_t len = (uint8_t)a[4]; const uint8_t *p = (const uint8_t *)(uintptr_t)a[3]; uint64_t s = 0;
      if (len) { if (!readable((uintptr_t)p, len) || (uint64_t)(uintptr_t)p != a[3]) violation("helper read", a[3], len); else { helper_ptr_ok++; for (uint8_t i = 0; i < len; i++) s += p[i]; } }
      return s;
    }
    case 6: {                                   // generic: check_ptr(addr=a0, len=(u32)a1, write=a2&1)
      bool w = a[2] & 1; uint32_t len = (uint32_t)a[1];
      if (!h2_bpf_check_ptr(m, a[0], len, w)) return 0;
      if ((uint64_t)(uintptr_t)a[0] != a[0] || len == 0 || !(w ? writable(a[0], len) : readable(a[0], len))) { violation(w ? "check_ptr write" : "check_ptr read", a[0], len); return 0; }
      helper_ptr_ok++;
      volatile uint8_t *p = (uint8_t *)(uintptr_t)a[0]; uint8_t s = 0; for (uint32_t i = 0; i < len; i++) { s += p[i]; if (w) p[i] = (uint8_t)i; }
      return 1 + s;
    }
    case 2: return a[0];
    case 3: return (uint64_t)(uintptr_t)m->stack;       // leak, for pointer forging
    default: *ok = false; return 0;
  }
}

// ---- assembler -----------------------------------------------------------------------------
static uint8_t *wp;
static void I(uint8_t op, int dst, int src, int off, int64_t imm) { wp[0] = op; wp[1] = (uint8_t)(dst | (src << 4)); wp[2] = (uint8_t)off; wp[3] = (uint8_t)((unsigned)off >> 8); uint32_t v = (uint32_t)imm; wp[4] = (uint8_t)v; wp[5] = (uint8_t)(v >> 8); wp[6] = (uint8_t)(v >> 16); wp[7] = (uint8_t)(v >> 24); wp += 8; }
static void LDDW(int dst, int src, uint64_t v) { I(0x18, dst, src, 0, (int64_t)(uint32_t)v); I(0, 0, 0, 0, (int64_t)(uint32_t)(v >> 32)); }

static unsigned st_count[8], accepted, okruns;
static h2_bpf_region_t region = { (const uint8_t *)&ctx, sizeof ctx, false };
static h2_bpf_status_t go(const uint8_t *image, uint32_t len, uint32_t budget, uint64_t *res, bool *acc)
{
  h2_bpf_image_t im; cur_img = image; cur_len = len;
  *acc = h2_bpf_parse(image, len, &im) && h2_bpf_verify(im.code, im.code_len, im.data_len, NULL) == H2_BPF_OK;
  if (!*acc) return H2_BPF_ERR_BAD_PROGRAM;
  accepted++;
  if (im.data && (im.data != im.code + im.code_len || im.data + im.data_len != image + len)) violation("parse layout", 0, 0);
  if (im.code_len + im.data_len + (im.code == image ? 0 : 8) != len) violation("parse lengths", 0, 0);
  vm.code = im.code; vm.code_len = im.code_len; vm.data = im.data; vm.data_len = im.data_len;   // vm is reused, as in the firmware
  vm.regions = &region; vm.region_count = 1; vm.helper = helper; vm.budget = budget;
  g_data = im.data; g_dlen = im.data_len;
  h2_bpf_status_t st = h2_bpf_run(&vm, (uint64_t)(uintptr_t)&ctx, res);
  st_count[st]++;
  low_invariant();
  if (st == H2_BPF_OK) { okruns++; if (vm.stack_low != vm.stack + H2_BPF_STACK_SIZE - H2_BPF_FRAME_SIZE) violation("stack_low after OK exit", 0, 0); }
  if (st == H2_BPF_ERR_BAD_PROGRAM) violation("verified program ran off the end / bad", vm.fault_pc, 0);
  if (vm.executed > budget + 1) violation("budget", vm.executed, budget);
  return st;
}

// ---- hand tests ----------------------------------------------------------------------------
static unsigned fails;
static void expect(const char *name, uint32_t len, bool want_acc, h2_bpf_status_t want, int check_r0, uint64_t r0)
{
  uint64_t r = 0; bool acc; h2_bpf_status_t st = go(img, len, 4000, &r, &acc);
  if (acc != want_acc || (acc && (st != want || (check_r0 && st == H2_BPF_OK && r != r0)))) {
    fails++; out("HAND FAIL: "); out(name); out(" acc="); outn(acc); out(" st="); outn(st); out(" r0="); outx(r); out(" pc="); outn(vm.fault_pc); out("\n");
  }
}
#define BEGIN() (wp = img)
#define LEN() ((uint32_t)(wp - img))
#define HDR(n, d) do { wp[0] = 0; wp[1] = 1; wp[2] = (uint8_t)(n); wp[3] = (uint8_t)((n) >> 8); wp[4] = (uint8_t)(d); wp[5] = (uint8_t)((d) >> 8); wp[6] = wp[7] = 0; wp += 8; } while (0)
#define EXIT() I(0x95, 0, 0, 0, 0)

static void hand(void)
{
  // recursion: f(n) writes its slice bottom (r10-128), recurses n times. main: r1=n; call f; exit
  for (int n = 0; n <= 6; n++) for (int below = 0; below < 2; below++) {
    BEGIN(); I(0xb7, 1, 0, 0, n); I(0x85, 0, 1, 0, 1); EXIT();
    /*3*/ I(0x7b, 10, 1, below ? -129 : -128, 0); I(0x73, 10, 1, -1, 0); I(0x15, 1, 0, 2, 0); I(0x07, 1, 0, 0, -1); I(0x85, 0, 1, 0, -5); I(0xb7, 0, 0, 0, 7); EXIT();
    // calls nest n+1 deep in total (f(n)..f(0)); depth limit allows 5 calls
    expect("recursion", LEN(), true, below ? H2_BPF_ERR_MEMORY : (n + 1 > 5 ? H2_BPF_ERR_DEPTH : H2_BPF_OK), 1, 7);
  }
  // callee returns pointer into its own (dead) slice; caller dereferences -> must fault
  BEGIN(); I(0x85, 0, 1, 0, 2); I(0x71, 0, 0, 0, 0); EXIT(); I(0xbf, 0, 10, 0, 0); I(0x07, 0, 0, 0, -8); EXIT();
  expect("dead callee slice", LEN(), true, H2_BPF_ERR_MEMORY, 0, 0);
  // callee reads all the way up through the callers' slices to the top of the stack (allowed), and one past (fault)
  for (int past = 0; past < 2; past++) { BEGIN(); I(0x85, 0, 1, 0, 1); EXIT(); I(0x71, 0, 10, 127 + past, 0); I(0xb7, 0, 0, 0, 1); EXIT();
    expect("callee to stack top", LEN(), true, past ? H2_BPF_ERR_MEMORY : H2_BPF_OK, 1, 1); }
  // r10 of the caller is restored after the callee returns, and after a helper call
  BEGIN(); I(0x7a, 10, 0, -8, 5); I(0x85, 0, 1, 0, 2); I(0x79, 0, 10, -8, 0); EXIT(); I(0x7a, 10, 0, -8, 9); I(0x85, 0, 0, 0, 2); EXIT();
  expect("r10 restored", LEN(), true, H2_BPF_OK, 1, 5);
  // fall through from main into a "function" that exits: exit at depth 0 ends the run
  BEGIN(); I(0xb7, 0, 0, 0, 3); I(0x15, 0, 0, 1, 99); /*fallthrough into f*/ I(0x07, 0, 0, 0, 1); EXIT();
  expect("fallthrough", LEN(), true, H2_BPF_OK, 1, 4);
  // jump from callee into the caller's code, then exit there: returns to after the call with stack_low in step
  BEGIN(); I(0x85, 0, 1, 0, 3); I(0x7a, 10, 0, -128, 1); I(0xb7, 0, 0, 0, 8); EXIT(); I(0x05, 0, 0, -2, 0);
  expect("callee jumps into caller", LEN(), true, H2_BPF_OK, 1, 8);
  // local call / jump / gotol into lddw second half
  BEGIN(); I(0x85, 0, 1, 0, 2); EXIT(); LDDW(0, 0, 0x9500000000ULL); EXIT(); expect("call into lddw half", LEN(), false, 0, 0, 0);
  BEGIN(); I(0x06, 0, 0, 0, 1); LDDW(0, 0, 0); EXIT(); expect("gotol into lddw half", LEN(), false, 0, 0, 0);
  BEGIN(); I(0x0e, 0, 0, 1, 0); LDDW(0, 0, 0); EXIT(); expect("ja32x into lddw half", LEN(), false, 0, 0, 0);
  BEGIN(); I(0x06, 0, 0, 1, 2); LDDW(0, 0, 0); EXIT(); expect("gotol with offset field refused", LEN(), false, 0, 0, 0);
  // lddw second half that itself looks like lddw, followed by a jump to the slot after it
  BEGIN(); I(0x05, 0, 0, 2, 0); I(0x18, 0, 0, 0, 0); I(0x18, 0, 0, 0, 0); EXIT(); expect("lddw half with opcode", LEN(), false, 0, 0, 0);
  // exit variants / odd encodings
  BEGIN(); I(0x9d, 0, 0, 0, 0); EXIT(); expect("exit with X bit refused", LEN(), false, 0, 0, 0);
  BEGIN(); I(0x8d, 0, 1, 0, 0); EXIT(); expect("callx", LEN(), false, 0, 0, 0);
  BEGIN(); I(0x85, 0, 1, 0, 0x7fffffff); EXIT(); expect("call imm max", LEN(), false, 0, 0, 0);
  BEGIN(); I(0x85, 0, 1, 0, (int32_t)0x80000000); EXIT(); expect("call imm min", LEN(), false, 0, 0, 0);
  BEGIN(); I(0x06, 0, 0, 0, (int32_t)0x80000000); EXIT(); expect("gotol imm min", LEN(), false, 0, 0, 0);
  BEGIN(); I(0xbf, 10, 1, 0, 0); EXIT(); expect("mov r10", LEN(), false, 0, 0, 0);
  BEGIN(); I(0x79, 10, 1, 0, 0); EXIT(); expect("ldx r10", LEN(), false, 0, 0, 0);
  BEGIN(); I(0xd4, 10, 0, 0, 16); EXIT(); expect("bswap r10", LEN(), false, 0, 0, 0);
  BEGIN(); I(0x87, 10, 0, 0, 0); EXIT(); expect("neg r10", LEN(), false, 0, 0, 0);
  BEGIN(); LDDW(10, 0, 0); EXIT(); expect("lddw r10", LEN(), false, 0, 0, 0);
  // pointer forging: 64-bit wrap must not validate (matters when uintptr_t is 32 bits)
  BEGIN(); LDDW(1, 0, 0x100000000ULL); I(0x0f, 1, 10, 0, 0); I(0x7a, 1, 0, -8, 1); I(0xb7, 0, 0, 0, 1); EXIT();
  expect("ptr + 2^32 store", LEN(), true, H2_BPF_ERR_MEMORY, 0, 0);
  BEGIN(); LDDW(1, 0, 0xffffffff00000000ULL); I(0x0f, 1, 10, 0, 0); I(0x71, 0, 1, -8, 0); EXIT();
  expect("ptr | high load", LEN(), true, H2_BPF_ERR_MEMORY, 0, 0);
  BEGIN(); LDDW(4, 0, 0x100000000ULL); I(0x0f, 4, 10, 0, 0); I(0x07, 4, 0, 0, -8); I(0xb7, 5, 0, 0, 4); I(0x85, 0, 0, 0, 5); EXIT();
  expect("helper ptr + 2^32", LEN(), true, H2_BPF_ERR_HELPER, 0, 0);
  // helper length: 2^32+4 must be refused (cap before truncation), 0 length accepted without check
  BEGIN(); I(0xbf, 4, 10, 0, 0); I(0x07, 4, 0, 0, -8); LDDW(5, 0, 0x100000004ULL); I(0x85, 0, 0, 0, 5); EXIT();
  expect("helper len 2^32+4", LEN(), true, H2_BPF_ERR_HELPER, 0, 0);
  BEGIN(); I(0xb7, 4, 0, 0, 1234); I(0xb7, 5, 0, 0, 0); I(0x85, 0, 0, 0, 5); EXIT();
  expect("helper len 0 wild ptr", LEN(), true, H2_BPF_OK, 1, 0);
  // helper buffer straddling the top of the stack / bottom of slice
  BEGIN(); I(0xbf, 4, 10, 0, 0); I(0x07, 4, 0, 0, -4); I(0xb7, 5, 0, 0, 5); I(0x85, 0, 0, 0, 5); EXIT();
  expect("helper past stack top", LEN(), true, H2_BPF_ERR_HELPER, 0, 0);
  BEGIN(); I(0xbf, 4, 10, 0, 0); I(0x07, 4, 0, 0, -129); I(0xb7, 5, 0, 0, 5); I(0x85, 0, 0, 0, 5); EXIT();
  expect("helper below slice", LEN(), true, H2_BPF_ERR_HELPER, 0, 0);
  // data: read last byte ok; straddle; one before (that is code); one past image; write
  for (int k = 0; k < 6; k++) {
    BEGIN(); HDR(5, 8); LDDW(1, 2, k == 5 ? 0 : 7);
    if (k == 0) I(0x71, 0, 1, 0, 0); if (k == 1) I(0x69, 0, 1, 0, 0); if (k == 2) I(0x71, 0, 1, -8, 0); if (k == 3) I(0x71, 0, 1, 1, 0); if (k == 4) I(0x72, 1, 0, 0, 1); if (k == 5) I(0x79, 0, 1, 0, 0);
    I(0xb7, 0, 0, 0, 1); EXIT(); for (int q = 0; q < 8; q++) *wp++ = (uint8_t)(q + 1);
    expect("data edges", LEN(), true, (k == 0 || k == 5) ? H2_BPF_OK : H2_BPF_ERR_MEMORY, 1, 1);
  }
  BEGIN(); HDR(5, 8); LDDW(4, 2, 4); I(0xb7, 5, 0, 0, 5); I(0x85, 0, 0, 0, 5); EXIT(); for (int q = 0; q < 8; q++) *wp++ = 1;
  expect("helper past data", LEN(), true, H2_BPF_ERR_HELPER, 0, 0);
  // header edge cases
  BEGIN(); HDR(3, 0xffff); LDDW(1, 2, 0); EXIT(); expect("hdr data too long", LEN(), false, 0, 0, 0);
  BEGIN(); HDR(0xffff, 8); EXIT(); expect("hdr insns too long", LEN(), false, 0, 0, 0);
  BEGIN(); HDR(1, 0); EXIT(); wp[-8 - 2] = 1; expect("hdr reserved", LEN(), false, 0, 0, 0);
  BEGIN(); HDR(1, 3); EXIT(); wp += 3; expect("hdr odd data len", LEN(), true, H2_BPF_OK, 0, 0);
  BEGIN(); HDR(3, 8); LDDW(1, 2, 0x80000000u); EXIT(); wp += 8; expect("lddw data negative", LEN(), false, 0, 0, 0);
  // a fault deep in the call stack, then a fresh run on the same vm: stack_low must be reset
  BEGIN(); I(0x85, 0, 1, 0, 1); EXIT(); I(0x85, 0, 1, 0, 0); I(0x85, 0, 1, 0, 0); I(0x71, 0, 0, 0, 0); EXIT();
  expect("fault at depth 3", LEN(), true, H2_BPF_ERR_MEMORY, 0, 0);
  BEGIN(); I(0x7a, 10, 0, -128, 1); I(0x79, 0, 10, -128, 0); EXIT(); expect("run after fault", LEN(), true, H2_BPF_OK, 1, 1);
  BEGIN(); I(0x7a, 10, 0, -136, 1); EXIT(); expect("run after fault, below", LEN(), true, H2_BPF_ERR_MEMORY, 0, 0);
  out("hand tests: "); outn(fails); out(" failures\n");
}

// ---- structured generator ------------------------------------------------------------------
static const int16_t soffs[] = { -1, -2, -4, -8, -16, -64, -120, -121, -124, -127, -128, -129, -132, -136, -255, -256, -257, -384, -512, -640, -641, -768, -769, 0, 1, 4, 8, 120, 127, 128, 248, 256, 632, 640 };
static const uint8_t ldops[] = { 0x61, 0x69, 0x71, 0x79, 0x81, 0x89, 0x91 }, stxops[] = { 0x63, 0x6b, 0x73, 0x7b }, stops[] = { 0x62, 0x6a, 0x72, 0x7a };
static const uint64_t bigs[] = { 0x100000000ULL, 0xffffffff00000000ULL, 0xffffffffffffffffULL, 0x80000000ULL, 0xffffffffULL, 0x100000004ULL, 128, 640, 768, 0x8000000000000000ULL };
static const int16_t lens[] = { 0, 1, 2, 8, 63, 64, 65, 127, 128, 129, 640, 768, 769 };
#define PICK(a) ((a)[R(sizeof(a) / sizeof((a)[0]))])

static uint32_t gen(void)
{
  uint32_t dlen = R(3) ? 8 * R(4) : 0;
  int nfun = 1 + R(5), total = 0; int start[6], flen[6];
  for (int f = 0; f < nfun; f++) { flen[f] = 3 + R(14); start[f] = total; total += flen[f]; }
  bool hdr = dlen || R(2);
  wp = img; if (hdr) HDR(total, dlen);
  uint8_t *code = wp;
  for (int f = 0; f < nfun; f++) {
    while ((wp - code) / 8 < start[f] + flen[f] - 1) {
      int pc = (int)((wp - code) / 8), room = start[f] + flen[f] - 1 - pc;
      int rp = 1 + R(9), rq = R(10);                      // rp: a register we like to keep pointers in
      switch (R(22)) {
        case 0: case 1: I(0xbf, rp, 10, 0, 0); break;                                 // r = r10
        case 2: I(0x07, rp, 0, 0, R(4) ? PICK(soffs) : (int32_t)rnd()); break;        // r += imm
        case 3: I(PICK(stxops), 10, rq, PICK(soffs), 0); break;
        case 4: I(PICK(stops), 10, 0, PICK(soffs), (int32_t)rnd()); break;
        case 5: I(PICK(ldops), rq, 10, PICK(soffs), 0); break;
        case 6: I(PICK(stxops), rp, rq, R(3) ? (int)R(17) - 8 : PICK(soffs), 0); break;
        case 7: I(PICK(ldops), rq, rp, R(3) ? (int)R(17) - 8 : PICK(soffs), 0); break;
        case 8: if (room >= 2) { if (dlen && R(8)) LDDW(rp, 2, R(dlen)); else LDDW(rp, R(12) ? 0 : 2, PICK(bigs)); } break;
        case 9: I(0x0f, rp, 1 + R(9), 0, 0); break;                                   // ptr += reg
        case 10: {                                                                     // local call
          int tgt = R(8) ? start[R(nfun)] : (int)R(total);
          if (R(6) == 0 && f + 1 < nfun) tgt = start[f + 1];
          I(0x85, 0, 1, 0, tgt - pc - 1); break; }
        case 11: {                                                                     // firmware-style helper
          if (room >= 4) { I(0xbf, 4, R(3) ? rp : 10, 0, 0); if (R(2)) I(0x07, 4, 0, 0, PICK(soffs)); I(0xb7, 5, 0, 0, PICK(lens)); I(0x85, 0, 0, 0, 5); } break; }
        case 12: {                                                                     // generic check_ptr helper
          if (room >= 6) { I(0xbf, 1, R(3) ? rp : 10, 0, 0); if (R(2)) I(0x07, 1, 0, 0, PICK(soffs)); if (R(4)) I(0xb7, 2, 0, 0, PICK(lens)); else LDDW(2, 0, PICK(bigs)); I(0xb7, 3, 0, 0, R(2)); I(0x85, 0, 0, 0, 6); } break; }
        case 13: I(0x85, 0, 0, 0, R(2) ? 3 : 2); if (R(2) && room >= 2) I(0xbf, rp, 0, 0, 0); break;   // leak stack base into a register
        case 14: { static const uint8_t j[] = { 0x05, 0x15, 0x1d, 0x25, 0x55, 0x65, 0xa5, 0x16, 0x56, 0xb5, 0x2d };
          int tgt = R(4) ? start[f] + (int)R(flen[f]) : (int)R(total); uint8_t op = PICK(j);
          if (R(6) == 0) I(0x06, 0, 0, 0, tgt - pc - 1); else I(op, rq, R(10), tgt - pc - 1, R(3)); break; }
        case 15: I(0x95, 0, 0, 0, 0); break;
        case 16: I(0xbf, rp, 1, 0, 0); break;                                         // ctx pointer (only meaningful at entry)
        case 17: { static const uint8_t a[] = { 0x07, 0x0f, 0x17, 0x1f, 0x27, 0x2f, 0x37, 0x3f, 0x47, 0x57, 0x67, 0x6f, 0x77, 0x7f, 0x87, 0x97, 0x9f, 0xa7, 0xaf, 0xb7, 0xbf, 0xc7, 0xcf, 0x04, 0x0c, 0x14, 0x34, 0x3c, 0x64, 0x6c, 0x74, 0x7c, 0x84, 0x94, 0x9c, 0xb4, 0xbc, 0xc4, 0xcc, 0xd4, 0xdc, 0xd7 };
          uint8_t op = PICK(a); int off = 0; int32_t imm = R(3) ? (int32_t)R(70) - 4 : (int32_t)rnd();
          if ((op >> 4) == 0xd) imm = 16 << R(3); if (((op >> 4) == 3 || (op >> 4) == 9) && R(2)) off = 1; if ((op == 0xbf || op == 0xbc) && R(2)) off = 8 << R(3);
          I(op, R(10), R(11), off, imm); break; }
        case 18: I(0xb7, 1 + R(5), 0, 0, R(3) ? PICK(lens) : (int32_t)rnd()); break;
        case 19: I(PICK(ldops), rq, 1, R(18), 0); break;                               // ctx load
        case 20: if (room >= 2 && dlen) { LDDW(rp, 2, R(dlen)); } break;
        default: I((uint8_t)rnd(), R(11), R(11), (int16_t)rnd(), (int32_t)rnd()); break;  // garbage
      }
    }
    I(R(12) ? 0x95 : 0x05, 0, 0, R(2) ? -1 : -(int)R(flen[f]), 0);
    if (wp[-8] == 0x95) { wp[-6] = wp[-5] = 0; }
  }
  for (uint32_t q = 0; q < dlen; q++) *wp++ = (uint8_t)rnd();
  uint32_t len = (uint32_t)(wp - img);
  if (R(5) == 0) { int k = 1 + R(3); while (k--) img[R(len)] = (uint8_t)rnd(); }      // light mutation
  return len;
}

#ifdef FREESTANDING
static void realmain(void);
void _start(void) { __asm__("and $-16, %esp"); realmain(); die(0); }
static void realmain(void)
{
  uint32_t total = 3000000;
#else
int main(int argc, char **argv)
{
  uint32_t total = argc > 1 ? (uint32_t)strtoul(argv[1], 0, 0) : 3000000;
  if (argc > 2) rs ^= strtoull(argv[2], 0, 0) * 0x9E3779B97F4A7C15ULL;
#endif
  out("uintptr bits: "); outn(sizeof(uintptr_t) * 8); out("\n");
  hand();
  for (uint32_t i = 0; i < total; i++) {
    uint32_t len = gen(); uint64_t r; bool acc;
    ctx.source = (uint8_t)rnd(); ctx.type = (uint8_t)rnd(); ctx.value = (int32_t)rnd(); ctx.millis = rnd();
    go(img, len, R(4) ? 400 : 4000, &r, &acc);
  }
  out("fuzz: "); outn(total); out(" generated, accepted "); outn(accepted); out(", OK "); outn(st_count[0]); out(" BUDGET "); outn(st_count[2]); out(" MEMORY "); outn(st_count[3]); out(" HELPER "); outn(st_count[4]); out(" DEPTH "); outn(st_count[5]);
  out("\n successful stack accesses by call depth 0..5:"); for (int d = 0; d < 6; d++) { out(" "); outn(acc_at_depth[d]); }
  out("\n data reads "); outn(data_reads); out(", ctx reads "); outn(ctx_reads); out(", helper calls "); outn(helper_calls); out(", helper pointers accepted "); outn(helper_ptr_ok);
  out("\n violations "); outn(violations); out(", hand failures "); outn(fails); out("\n");
#ifndef FREESTANDING
  return violations || fails;
#endif
}
