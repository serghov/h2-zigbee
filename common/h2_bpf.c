#include "h2_bpf.h"
#include <string.h>

// Instruction layout: opcode(8) | dst(4) src(4) | offset(16, signed) | imm(32, signed)
#define OPC(p)   ((p)[0])
#define DST(p)   ((p)[1] & 0x0F)
#define SRC(p)   ((p)[1] >> 4)
static inline int16_t OFF(const uint8_t *p) { return (int16_t)(p[2] | (p[3] << 8)); }
static inline int32_t IMM(const uint8_t *p)
{
  return (int32_t)((uint32_t)p[4] | ((uint32_t)p[5] << 8) | ((uint32_t)p[6] << 16) | ((uint32_t)p[7] << 24));
}

#define CLS(op)        ((op) & 0x07)
#define CLS_LD         0x00
#define CLS_LDX        0x01
#define CLS_ST         0x02
#define CLS_STX        0x03
#define CLS_ALU        0x04
#define CLS_JMP        0x05
#define CLS_JMP32      0x06
#define CLS_ALU64      0x07

#define OP_LDDW        0x18
#define MODE_MEM       0x60
#define MODE_MEMSX     0x80       // sign-extending load (v4)
#define SRC_X          0x08

static uint8_t size_of(uint8_t op)
{
  switch (op & 0x18) {
    case 0x00: return 4;
    case 0x08: return 2;
    case 0x10: return 1;
    default:   return 8;
  }
}

// Target of a jump instruction at index pc. "ja" in the 32-bit jump class (v4 "gotol")
// carries its offset in the immediate.
static int64_t jump_target(const uint8_t *p, uint32_t pc)
{
  if (OPC(p) == 0x06) return (int64_t)pc + 1 + IMM(p);
  return (int64_t)pc + 1 + OFF(p);
}

static bool alu_op_known(uint8_t op)
{
  uint8_t code = op >> 4;
  if (code > 0x0D) return false;
  if (code == 0x08 && (op & SRC_X)) return false;      // neg takes no source
  return true;
}

h2_bpf_status_t h2_bpf_verify(const uint8_t *code, uint32_t code_len, uint32_t *bad_pc)
{
  uint32_t n = code_len / 8;
  uint32_t pc = 0;
  #define BAD() do { if (bad_pc) *bad_pc = pc; return H2_BPF_ERR_BAD_PROGRAM; } while (0)

  if (code_len == 0 || (code_len & 7) != 0) BAD();

  // Pass 1: decode every instruction, remember which slots are lddw second halves.
  for (pc = 0; pc < n; pc++) {
    const uint8_t *p = code + pc * 8;
    uint8_t op = OPC(p), dst = DST(p), src = SRC(p);
    if (dst > 10 || src > 10) BAD();

    switch (CLS(op)) {
      case CLS_LD:
        if (op != OP_LDDW || src != 0 || dst == 10) BAD();
        if (pc + 1 >= n) BAD();
        if (OPC(p + 8) != 0 || p[9] != 0 || OFF(p + 8) != 0) BAD();
        pc++;                                            // skip the second half
        break;
      case CLS_LDX:
        if (dst == 10) BAD();
        if ((op & 0xE0) == MODE_MEMSX) { if (size_of(op) == 8) BAD(); }
        else if ((op & 0xE0) != MODE_MEM) BAD();
        break;
      case CLS_ST:
      case CLS_STX:
        if ((op & 0xE0) != MODE_MEM) BAD();
        break;
      case CLS_ALU:
      case CLS_ALU64:
        if (!alu_op_known(op) || dst == 10) BAD();
        if ((op >> 4) == 0x0D) {                         // byte swap
          int32_t w = IMM(p);
          if (w != 16 && w != 32 && w != 64) BAD();
          if (CLS(op) == CLS_ALU64 && (op & SRC_X)) BAD();
        } else if ((op >> 4) == 0x03 || (op >> 4) == 0x09) {
          if (OFF(p) != 0 && OFF(p) != 1) BAD();         // 1 = signed div/mod (v4)
        } else if ((op >> 4) == 0x0B && (op & SRC_X)) {
          int16_t w = OFF(p);                            // sign-extending mov (v4)
          if (w != 0 && w != 8 && w != 16 && !(w == 32 && CLS(op) == CLS_ALU64)) BAD();
        } else if (OFF(p) != 0) {
          BAD();
        }
        break;
      case CLS_JMP:
      case CLS_JMP32: {
        uint8_t jop = op >> 4;
        if (jop == 0x08) {                               // call
          if (CLS(op) != CLS_JMP || (op & SRC_X) || src != 0) BAD();   // host helpers only
        } else if (jop == 0x09) {                        // exit
          if (CLS(op) != CLS_JMP) BAD();
        } else if (jop <= 0x0D) {
          int64_t target = jump_target(p, pc);
          if (target < 0 || target >= (int64_t)n) BAD();
        } else {
          BAD();
        }
        break;
      }
    }
  }

  // Pass 2: jump targets must not land on the second half of a lddw, and the last
  // instruction must not fall through.
  for (pc = 0; pc < n; pc++) {
    const uint8_t *p = code + pc * 8;
    uint8_t op = OPC(p);
    if (op == OP_LDDW) { pc++; continue; }
    if ((CLS(op) == CLS_JMP || CLS(op) == CLS_JMP32) && (op >> 4) != 0x08 && (op >> 4) != 0x09) {
      uint32_t target = (uint32_t)jump_target(p, pc);
      // A second half always has opcode 0, so opcode lddw at target-1 means a first half.
      if (target > 0 && OPC(code + (target - 1) * 8) == OP_LDDW) BAD();
    }
  }
  {
    // Find the real last instruction (accounting for lddw pairs).
    uint32_t q = 0, last = 0;
    while (q < n) { last = q; q += (OPC(code + q * 8) == OP_LDDW) ? 2 : 1; }
    uint8_t op = OPC(code + last * 8);
    bool is_exit = (op == 0x95);
    bool is_ja = (op == 0x05 || op == 0x06);
    pc = last;
    if (!is_exit && !is_ja) BAD();
  }
  #undef BAD
  return H2_BPF_OK;
}

bool h2_bpf_check_ptr(const h2_bpf_vm_t *vm, uint64_t addr, uint32_t len, bool write)
{
  uintptr_t a = (uintptr_t)addr;
  if ((uint64_t)a != addr || len == 0) return false;
  uintptr_t sb = (uintptr_t)vm->stack;
  if (a >= sb && a - sb <= H2_BPF_STACK_SIZE && len <= H2_BPF_STACK_SIZE - (a - sb)) return true;
  for (uint8_t i = 0; i < vm->region_count; i++) {
    const h2_bpf_region_t *r = &vm->regions[i];
    uintptr_t rb = (uintptr_t)r->base;
    if (a >= rb && a - rb <= r->len && len <= r->len - (a - rb)) {
      return !write || r->writable;
    }
  }
  return false;
}

h2_bpf_status_t h2_bpf_run(h2_bpf_vm_t *vm, uint64_t ctx, uint64_t *result)
{
  uint64_t reg[11];
  memset(reg, 0, sizeof(reg));
  memset(vm->stack, 0, sizeof(vm->stack));
  reg[1] = ctx;
  reg[10] = (uint64_t)(uintptr_t)(vm->stack + H2_BPF_STACK_SIZE);

  const uint32_t n = vm->code_len / 8;
  uint32_t pc = 0;
  vm->executed = 0;

  #define FAIL(st) do { vm->fault_pc = pc; return (st); } while (0)

  while (pc < n) {
    if (vm->executed++ >= vm->budget) FAIL(H2_BPF_ERR_BUDGET);

    const uint8_t *p = vm->code + pc * 8;
    uint8_t op = OPC(p), dst = DST(p), src = SRC(p);
    int16_t off = OFF(p);
    int32_t imm = IMM(p);

    switch (CLS(op)) {
      case CLS_LD:                                       // lddw (verified)
        reg[dst] = (uint64_t)(uint32_t)imm | ((uint64_t)(uint32_t)IMM(p + 8) << 32);
        pc += 2;
        continue;

      case CLS_LDX: {
        uint8_t sz = size_of(op);
        uint64_t addr = reg[src] + (int64_t)off;
        if (!h2_bpf_check_ptr(vm, addr, sz, false)) FAIL(H2_BPF_ERR_MEMORY);
        uint64_t v = 0;
        memcpy(&v, (const void *)(uintptr_t)addr, sz);   // little-endian host
        if ((op & 0xE0) == MODE_MEMSX) {
          if (sz == 1) v = (uint64_t)(int64_t)(int8_t)v;
          else if (sz == 2) v = (uint64_t)(int64_t)(int16_t)v;
          else v = (uint64_t)(int64_t)(int32_t)v;
        }
        reg[dst] = v;
        break;
      }

      case CLS_ST:
      case CLS_STX: {
        uint8_t sz = size_of(op);
        uint64_t addr = reg[dst] + (int64_t)off;
        if (!h2_bpf_check_ptr(vm, addr, sz, true)) FAIL(H2_BPF_ERR_MEMORY);
        uint64_t v = (CLS(op) == CLS_STX) ? reg[src] : (uint64_t)(int64_t)imm;
        memcpy((void *)(uintptr_t)addr, &v, sz);
        break;
      }

      case CLS_ALU:
      case CLS_ALU64: {
        bool is64 = (CLS(op) == CLS_ALU64);
        uint64_t a = reg[dst];
        uint64_t b = (op & SRC_X) ? reg[src] : (uint64_t)(int64_t)imm;
        if (!is64) { a = (uint32_t)a; b = (uint32_t)b; }
        uint64_t r = a;
        uint8_t aop = op >> 4;
        if ((aop == 0x3 || aop == 0x9) && off == 1) {                // signed div / mod (v4)
          int64_t sa = is64 ? (int64_t)a : (int64_t)(int32_t)(uint32_t)a;
          int64_t sb = is64 ? (int64_t)b : (int64_t)(int32_t)(uint32_t)b;
          int64_t sr;
          if (sb == 0)       sr = (aop == 0x3) ? 0 : sa;
          else if (sb == -1) sr = (aop == 0x3) ? (int64_t)(0 - (uint64_t)sa) : 0;   // no overflow trap
          else               sr = (aop == 0x3) ? sa / sb : sa % sb;
          reg[dst] = is64 ? (uint64_t)sr : (uint64_t)(uint32_t)sr;
          pc++;
          continue;
        }
        if (aop == 0xB && off != 0) {                                // sign-extending mov (v4)
          int64_t sv = (off == 8) ? (int8_t)reg[src] : (off == 16) ? (int16_t)reg[src] : (int32_t)reg[src];
          reg[dst] = is64 ? (uint64_t)sv : (uint64_t)(uint32_t)sv;
          pc++;
          continue;
        }
        switch (aop) {
          case 0x0: r = a + b; break;
          case 0x1: r = a - b; break;
          case 0x2: r = a * b; break;
          case 0x3: r = (b == 0) ? 0 : a / b; break;                 // division by zero gives 0
          case 0x4: r = a | b; break;
          case 0x5: r = a & b; break;
          case 0x6: r = is64 ? (a << (b & 63)) : (uint64_t)((uint32_t)a << (b & 31)); break;
          case 0x7: r = is64 ? (a >> (b & 63)) : (uint64_t)((uint32_t)a >> (b & 31)); break;
          case 0x8: r = 0 - a; break;
          case 0x9: r = (b == 0) ? a : a % b; break;                 // modulo by zero keeps dst
          case 0xA: r = a ^ b; break;
          case 0xB: r = b; break;
          case 0xC: r = is64 ? (uint64_t)((int64_t)a >> (b & 63))
                             : (uint64_t)(uint32_t)((int32_t)(uint32_t)a >> (b & 31)); break;
          case 0xD: {                                                // byte swap / truncate
            // to-little-endian on a little-endian host only truncates; to-big-endian swaps
            uint64_t full = reg[dst];
            if ((op & SRC_X) || is64) {                              // to-BE, or v4 unconditional swap
              if (imm == 16) r = (uint64_t)(uint16_t)(((full & 0xFF) << 8) | ((full >> 8) & 0xFF));
              else if (imm == 32) r = (uint64_t)__builtin_bswap32((uint32_t)full);
              else r = __builtin_bswap64(full);
            } else {
              if (imm == 16) r = (uint16_t)full;
              else if (imm == 32) r = (uint32_t)full;
              else r = full;
            }
            reg[dst] = r;
            pc++;
            continue;
          }
        }
        reg[dst] = is64 ? r : (uint64_t)(uint32_t)r;
        break;
      }

      case CLS_JMP:
      case CLS_JMP32: {
        uint8_t jop = op >> 4;
        if (jop == 0x9) {                                // exit
          if (result) *result = reg[0];
          return H2_BPF_OK;
        }
        if (jop == 0x8) {                                // call host helper
          bool ok = true;
          uint64_t args[5] = { reg[1], reg[2], reg[3], reg[4], reg[5] };
          if (vm->helper == NULL) FAIL(H2_BPF_ERR_HELPER);
          uint64_t r0 = vm->helper(vm, (uint32_t)imm, args, &ok);
          if (!ok) FAIL(H2_BPF_ERR_HELPER);
          reg[0] = r0;
          reg[1] = reg[2] = reg[3] = reg[4] = reg[5] = 0;   // caller-saved: do not leak
          break;
        }
        bool is64 = (CLS(op) == CLS_JMP);
        uint64_t a = reg[dst];
        uint64_t b = (op & SRC_X) ? reg[src] : (uint64_t)(int64_t)imm;
        int64_t sa, sb;
        if (is64) { sa = (int64_t)a; sb = (int64_t)b; }
        else { a = (uint32_t)a; b = (uint32_t)b; sa = (int32_t)(uint32_t)a; sb = (int32_t)(uint32_t)b; }
        bool take;
        switch (jop) {
          case 0x0: take = true; break;
          case 0x1: take = (a == b); break;
          case 0x2: take = (a > b); break;
          case 0x3: take = (a >= b); break;
          case 0x4: take = (a & b) != 0; break;
          case 0x5: take = (a != b); break;
          case 0x6: take = (sa > sb); break;
          case 0x7: take = (sa >= sb); break;
          case 0xA: take = (a < b); break;
          case 0xB: take = (a <= b); break;
          case 0xC: take = (sa < sb); break;
          default:  take = (sa <= sb); break;           // 0xD
        }
        if (take) {
          pc = (uint32_t)jump_target(p, pc);
          continue;
        }
        break;
      }
    }
    pc++;
  }
  FAIL(H2_BPF_ERR_BAD_PROGRAM);                          // ran off the end (verify prevents it)
  #undef FAIL
}
