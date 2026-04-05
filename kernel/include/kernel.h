#ifndef AEGIS_KERNEL_H
#define AEGIS_KERNEL_H

#include <stddef.h>
#include <stdint.h>

#define AEGIS_SCHEDULER_SNAPSHOT_SCHEMA_VERSION 2u
#define AEGIS_SCHEDULER_REASON_HISTOGRAM_WINDOW 32u
#define AEGIS_VM_REGION_CAPACITY 64u
#define AEGIS_IPC_ENVELOPE_SCHEMA_VERSION 1u

typedef struct {
  uint64_t base;
  uint64_t size;
  uint32_t flags;
  uint8_t active;
} aegis_vm_region_t;

typedef struct {
  aegis_vm_region_t regions[AEGIS_VM_REGION_CAPACITY];
  size_t count;
} aegis_vm_space_t;

typedef struct {
  uint16_t schema_version;
  uint16_t message_type;
  uint32_t flags;
  uint32_t payload_size;
  uint32_t correlation_id;
} aegis_ipc_envelope_t;

typedef struct {
  uint32_t process_ids[64];
  uint8_t priorities[64];
  uint8_t credits[64];
  uint32_t dispatch_counts[64];
  uint64_t enqueued_tick[64];
  uint64_t wait_ticks_total[64];
  uint64_t last_wait_latency[64];
  uint64_t total_dispatches;
  uint64_t scheduler_ticks;
  size_t high_watermark;
  uint32_t current_pid;
  uint8_t pending_switch_reason;
  uint64_t reason_switch_counts[5];
  uint8_t reason_switch_window[AEGIS_SCHEDULER_REASON_HISTOGRAM_WINDOW];
  uint32_t reason_switch_window_head;
  uint32_t reason_switch_window_count;
  uint32_t quantum_ticks;
  uint32_t quantum_remaining;
  size_t count;
  size_t head;
} aegis_scheduler_t;

typedef struct {
  uint32_t schema_version;
  size_t queue_depth;
  size_t high_watermark;
  uint64_t total_dispatches;
  uint64_t scheduler_ticks;
  uint32_t current_pid;
  uint32_t quantum_ticks;
  uint32_t quantum_remaining;
  uint64_t switch_process_start_count;
  uint64_t switch_quantum_expired_count;
  uint64_t switch_process_exit_count;
  uint64_t switch_manual_yield_count;
  uint32_t switch_reason_window_capacity;
  uint32_t switch_reason_window_samples;
  uint64_t recent_switch_process_start_count;
  uint64_t recent_switch_quantum_expired_count;
  uint64_t recent_switch_process_exit_count;
  uint64_t recent_switch_manual_yield_count;
} aegis_scheduler_metrics_snapshot_t;

typedef struct {
  uint64_t mean_wait_ticks;
  uint64_t p95_wait_ticks;
  uint64_t max_wait_ticks;
  uint64_t mean_last_latency_ticks;
  uint64_t p95_last_latency_ticks;
  uint64_t max_last_latency_ticks;
} aegis_scheduler_wait_report_t;

typedef struct {
  uint64_t captured_at_tick;
  size_t queue_depth;
  uint64_t total_dispatches;
  aegis_scheduler_wait_report_t report;
} aegis_scheduler_wait_report_snapshot_t;

typedef enum {
  AEGIS_PRIORITY_LOW = 1,
  AEGIS_PRIORITY_NORMAL = 2,
  AEGIS_PRIORITY_HIGH = 3
} aegis_scheduler_priority_t;

typedef enum {
  AEGIS_SWITCH_NONE = 0,
  AEGIS_SWITCH_PROCESS_START = 1,
  AEGIS_SWITCH_QUANTUM_EXPIRED = 2,
  AEGIS_SWITCH_PROCESS_EXIT = 3,
  AEGIS_SWITCH_MANUAL_YIELD = 4
} aegis_scheduler_switch_reason_t;

int aegis_kernel_boot_check(void);
void aegis_vm_space_init(aegis_vm_space_t *space);
int aegis_vm_map(aegis_vm_space_t *space, uint64_t base, uint64_t size, uint32_t flags);
int aegis_vm_unmap(aegis_vm_space_t *space, uint64_t base, uint64_t size);
int aegis_vm_query(const aegis_vm_space_t *space, uint64_t address, aegis_vm_region_t *region);
int aegis_vm_summary_json(const aegis_vm_space_t *space, char *out, size_t out_size);
int aegis_vm_update_flags(aegis_vm_space_t *space, uint64_t base, uint64_t size, uint32_t flags);
int aegis_vm_split_region(aegis_vm_space_t *space,
                          uint64_t base,
                          uint64_t size,
                          uint64_t split_offset);
int aegis_ipc_envelope_validate(const aegis_ipc_envelope_t *envelope, uint32_t max_payload_size);
int aegis_ipc_envelope_payload_fits(const aegis_ipc_envelope_t *envelope,
                                    uint32_t max_frame_size,
                                    uint32_t *remaining_bytes);
int aegis_ipc_envelope_encode(const aegis_ipc_envelope_t *envelope, uint8_t *out, size_t out_size);
int aegis_ipc_envelope_decode(const uint8_t *in, size_t in_size, aegis_ipc_envelope_t *envelope);
void aegis_scheduler_init(aegis_scheduler_t *scheduler);
int aegis_scheduler_add(aegis_scheduler_t *scheduler, uint32_t process_id);
int aegis_scheduler_add_with_priority(aegis_scheduler_t *scheduler, uint32_t process_id,
                                      uint8_t priority);
int aegis_scheduler_remove(aegis_scheduler_t *scheduler, uint32_t process_id);
int aegis_scheduler_set_priority(aegis_scheduler_t *scheduler, uint32_t process_id, uint8_t priority);
int aegis_scheduler_next(aegis_scheduler_t *scheduler, uint32_t *process_id);
size_t aegis_scheduler_count(const aegis_scheduler_t *scheduler);
uint64_t aegis_scheduler_total_dispatches(const aegis_scheduler_t *scheduler);
size_t aegis_scheduler_high_watermark(const aegis_scheduler_t *scheduler);
int aegis_scheduler_dispatch_count_for(const aegis_scheduler_t *scheduler, uint32_t process_id,
                                       uint32_t *dispatch_count);
void aegis_scheduler_reset_metrics(aegis_scheduler_t *scheduler);
void aegis_scheduler_set_quantum(aegis_scheduler_t *scheduler, uint32_t quantum_ticks);
int aegis_scheduler_on_tick(aegis_scheduler_t *scheduler, uint32_t *running_pid,
                            uint8_t *context_switch);
int aegis_scheduler_on_tick_ex(aegis_scheduler_t *scheduler, uint32_t *running_pid,
                               uint8_t *context_switch, uint8_t *switch_reason);
int aegis_scheduler_manual_yield(aegis_scheduler_t *scheduler);
int aegis_scheduler_metrics_snapshot(const aegis_scheduler_t *scheduler,
                                     aegis_scheduler_metrics_snapshot_t *snapshot);
int aegis_scheduler_metrics_snapshot_json(const aegis_scheduler_metrics_snapshot_t *snapshot,
                                          char *out, size_t out_size);
int aegis_scheduler_wait_ticks_for(const aegis_scheduler_t *scheduler, uint32_t process_id,
                                   uint64_t *wait_ticks);
int aegis_scheduler_last_latency_for(const aegis_scheduler_t *scheduler, uint32_t process_id,
                                     uint64_t *latency_ticks);
int aegis_scheduler_wait_report(const aegis_scheduler_t *scheduler,
                                aegis_scheduler_wait_report_t *report);
int aegis_scheduler_wait_report_snapshot(const aegis_scheduler_t *scheduler,
                                         aegis_scheduler_wait_report_snapshot_t *snapshot);
int aegis_scheduler_wait_report_snapshot_json(const aegis_scheduler_wait_report_snapshot_t *snapshot,
                                              char *out, size_t out_size);
int aegis_scheduler_switch_reason_count(const aegis_scheduler_t *scheduler, uint8_t switch_reason,
                                        uint64_t *count);
int aegis_scheduler_switch_reason_histogram_window(const aegis_scheduler_t *scheduler,
                                                   uint32_t requested_window,
                                                   uint32_t *applied_window,
                                                   uint64_t *process_start_count,
                                                   uint64_t *quantum_expired_count,
                                                   uint64_t *process_exit_count,
                                                   uint64_t *manual_yield_count);
int aegis_scheduler_switch_reason_histogram_window_json(const aegis_scheduler_t *scheduler,
                                                        uint32_t requested_window,
                                                        char *out,
                                                        size_t out_size);
int aegis_scheduler_fairness_snapshot_json(const aegis_scheduler_t *scheduler,
                                           char *out,
                                           size_t out_size);

#endif
