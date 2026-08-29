#ifndef CPUCYCLES_H
#define CPUCYCLES_H

#include <stdint.h>

/*
 * Minimal cycle counter for benchmarking, in the spirit of SUPERCOP/pqclean.
 *
 * x86/x86-64: RDTSC. This is the invariant TSC (a fixed-frequency reference
 *             clock), so the value is "reference cycles" at the nominal base
 *             frequency, not retired core cycles. That is the standard PQC
 *             benchmarking convention; for true core cycles build with perf
 *             counters (RDPMC), which needs privileged setup and is out of
 *             scope here.
 * aarch64:    CNTVCT_EL0, the virtual system counter. It is a fixed-frequency
 *             tick counter (typically ~24MHz), NOT core cycles -- treat the
 *             numbers as ticks, useful for relative comparisons only.
 * other:      returns 0 (no counter available).
 *
 * CPUCYCLES_UNIT names the unit so callers can label their output honestly.
 */

#if defined(__x86_64__) || defined(__i386__)
#define CPUCYCLES_UNIT "cycles (rdtsc)"
static inline uint64_t cpucycles(void) {
  uint32_t lo, hi;
  __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
  return ((uint64_t)hi << 32) | (uint64_t)lo;
}
#elif defined(__aarch64__)
#define CPUCYCLES_UNIT "ticks (cntvct_el0)"
static inline uint64_t cpucycles(void) {
  uint64_t v;
  __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(v));
  return v;
}
#else
#define CPUCYCLES_UNIT "n/a"
static inline uint64_t cpucycles(void) { return 0; }
#endif

#endif  // CPUCYCLES_H
