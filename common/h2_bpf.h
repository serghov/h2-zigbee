#ifndef H2_BPF_H
#define H2_BPF_H

// A small eBPF interpreter for rule programs.
//
// Runs programs for the BPF instruction set (RFC 9669) as produced by
// `clang -target bpf -mcpu=v4`. It is deliberately a subset: 64- and 32-bit arithmetic,
// conditional and unconditional jumps, signed division, sign extension, loads and
// stores to memory, 64-bit immediates, calls to host functions by number, calls between
// the program's own functions, read-only constant data, and exit. No maps, no atomics,
// no writable global data.
//
// A program image is either a bare instruction stream, or a header followed by the
// instructions and then the constant data (see h2_bpf_parse).
//
// Safety model, since programs arrive over the air and run on a mains switch:
//   - h2_bpf_verify() rejects malformed programs before they are ever run: unknown
//     opcodes, bad register numbers, jumps out of range or into the second half of a
//     64-bit immediate, writes to the frame pointer, and code that can fall off the end.
//   - every memory access is checked at run time against the regions the host passes in
//     (stack, event context, anything else), including write permission.
//   - every run has an instruction budget; exceeding it stops the program.
//   - calls between program functions are limited in depth, and each call gets its own
//     slice of the stack: a function cannot reach below its own slice, so one that needs
//     more stack than a slice holds stops with a memory fault instead of overwriting
//     another call's data.
// A program can compute the wrong thing, but it cannot read or write outside its regions
// or run forever.
//
// This file has no dependencies beyond the C library, so it builds on a PC for testing.

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define H2_BPF_FRAME_SIZE   128     // stack available to each function call
#define H2_BPF_MAX_DEPTH    6       // on_event plus five nested calls
#define H2_BPF_STACK_SIZE   (H2_BPF_FRAME_SIZE * H2_BPF_MAX_DEPTH)

// Image header (8 bytes, the size of one instruction; its first byte is not a valid
// opcode, so a bare instruction stream can never be mistaken for it):
//   [0] 0x00   [1] format version (1)   [2..3] number of instructions, little-endian
//   [4..5] bytes of constant data after the instructions   [6..7] zero
#define H2_BPF_IMAGE_VERSION  1

typedef struct {
  const uint8_t *code;       // instructions, 8 bytes each
  uint32_t code_len;         // in bytes
  const uint8_t *data;       // constant data, or NULL
  uint32_t data_len;
} h2_bpf_image_t;

// Split an image into code and constant data. False if the header is inconsistent.
bool h2_bpf_parse(const uint8_t *image, uint32_t image_len, h2_bpf_image_t *out);

typedef enum {
  H2_BPF_OK = 0,
  H2_BPF_ERR_BAD_PROGRAM,     // failed verification
  H2_BPF_ERR_BUDGET,          // instruction budget exhausted
  H2_BPF_ERR_MEMORY,          // access outside the permitted regions
  H2_BPF_ERR_HELPER,          // unknown helper or helper refused the call
  H2_BPF_ERR_DEPTH,           // calls between program functions nested too deeply
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
  const uint8_t *data;              // constant data of the image (read-only), or NULL
  uint32_t data_len;
  // filled in by h2_bpf_run():
  uint32_t executed;
  uint32_t fault_pc;                // instruction index where a failed run stopped
  uint8_t *stack_low;               // lowest stack address the running function may touch
  uint8_t stack[H2_BPF_STACK_SIZE];
} h2_bpf_vm_t;

// Static checks. Returns H2_BPF_OK or H2_BPF_ERR_BAD_PROGRAM (*bad_pc = offending index).
// data_len is the size of the image's constant data (0 if none): references to it are
// checked against that size.
h2_bpf_status_t h2_bpf_verify(const uint8_t *code, uint32_t code_len, uint32_t data_len,
                              uint32_t *bad_pc);

// Run the program with r1 = ctx. The program must have passed h2_bpf_verify().
// On H2_BPF_OK, *result receives r0.
h2_bpf_status_t h2_bpf_run(h2_bpf_vm_t *vm, uint64_t ctx, uint64_t *result);

// For helpers: is [addr, addr+len) inside one permitted region (and writable if asked)?
bool h2_bpf_check_ptr(const h2_bpf_vm_t *vm, uint64_t addr, uint32_t len, bool write);

#endif // H2_BPF_H
