#ifndef H2_BPF_H
#define H2_BPF_H

// A small eBPF interpreter for rule programs.
//
// Runs programs for the BPF instruction set (RFC 9669) as produced by
// `clang -target bpf -mcpu=v4`. It is deliberately a subset: 64- and 32-bit arithmetic,
// conditional and unconditional jumps, signed division, sign extension, loads and
// stores to memory, 64-bit immediates,
// calls to host functions by number, and exit. No maps, no BPF-to-BPF calls, no atomics.
//
// Safety model, since programs arrive over the air and run on a mains switch:
//   - h2_bpf_verify() rejects malformed programs before they are ever run: unknown
//     opcodes, bad register numbers, jumps out of range or into the second half of a
//     64-bit immediate, writes to the frame pointer, and code that can fall off the end.
//   - every memory access is checked at run time against the regions the host passes in
//     (stack, event context, anything else), including write permission.
//   - every run has an instruction budget; exceeding it stops the program.
// A program can compute the wrong thing, but it cannot read or write outside its regions
// or run forever.
//
// This file has no dependencies beyond the C library, so it builds on a PC for testing.

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define H2_BPF_STACK_SIZE   256

typedef enum {
  H2_BPF_OK = 0,
  H2_BPF_ERR_BAD_PROGRAM,     // failed verification
  H2_BPF_ERR_BUDGET,          // instruction budget exhausted
  H2_BPF_ERR_MEMORY,          // access outside the permitted regions
  H2_BPF_ERR_HELPER,          // unknown helper or helper refused the call
} h2_bpf_status_t;

typedef struct {
  const uint8_t *base;
  uint32_t len;
  bool writable;
} h2_bpf_region_t;

// Host function call. `id` is the immediate of the call instruction; args are r1..r5.
// Return the value for r0. Set *ok to false to abort the program.
// `vm` lets the helper validate pointers passed by the program (h2_bpf_check_ptr).
struct h2_bpf_vm;
typedef uint64_t (*h2_bpf_helper_t)(struct h2_bpf_vm *vm, uint32_t id, const uint64_t args[5], bool *ok);

typedef struct h2_bpf_vm {
  const uint8_t *code;              // instructions, 8 bytes each
  uint32_t code_len;                // in bytes
  const h2_bpf_region_t *regions;   // extra memory regions (the stack is added by the VM)
  uint8_t region_count;
  h2_bpf_helper_t helper;
  void *user;                       // for the helper's use
  uint32_t budget;                  // max instructions per run
  // filled in by h2_bpf_run():
  uint32_t executed;
  uint32_t fault_pc;                // instruction index where a failed run stopped
  uint8_t stack[H2_BPF_STACK_SIZE];
} h2_bpf_vm_t;

// Static checks. Returns H2_BPF_OK or H2_BPF_ERR_BAD_PROGRAM (*bad_pc = offending index).
h2_bpf_status_t h2_bpf_verify(const uint8_t *code, uint32_t code_len, uint32_t *bad_pc);

// Run the program with r1 = ctx. The program must have passed h2_bpf_verify().
// On H2_BPF_OK, *result receives r0.
h2_bpf_status_t h2_bpf_run(h2_bpf_vm_t *vm, uint64_t ctx, uint64_t *result);

// For helpers: is [addr, addr+len) inside one permitted region (and writable if asked)?
bool h2_bpf_check_ptr(const h2_bpf_vm_t *vm, uint64_t addr, uint32_t len, bool write);

#endif // H2_BPF_H
