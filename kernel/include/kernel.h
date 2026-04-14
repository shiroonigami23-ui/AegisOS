#ifndef AEGIS_KERNEL_H
#define AEGIS_KERNEL_H

#include <stddef.h>
#include <stdint.h>

#define AEGIS_SCHEDULER_SNAPSHOT_SCHEMA_VERSION 2u
#define AEGIS_SCHEDULER_REASON_HISTOGRAM_WINDOW 32u
#define AEGIS_VM_REGION_CAPACITY 64u
#define AEGIS_IPC_ENVELOPE_SCHEMA_VERSION 1u
#define AEGIS_NAMESPACE_CAPACITY 64u
#define AEGIS_NAMESPACE_PROCESS_CAPACITY 256u
#define AEGIS_SYSCALL_GATE_CAPACITY 128u
#define AEGIS_SYSCALL_RULE_CAPACITY 64u
#define AEGIS_IPC_CHANNEL_CAPACITY 64u
#define AEGIS_MEMORY_ZONE_CAPACITY 16u
#define AEGIS_PROCESS_CHECKPOINT_CAPACITY 128u
#define AEGIS_PROCESS_CHECKPOINT_TAG_MAX 48u
#define AEGIS_TIME_ATTEST_NONCE_MAX 32u

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
  uint8_t admission_limits[4];
  uint8_t priority_counts[4];
  uint8_t runnable_priority_counts[4];
  uint8_t priority_present_bitmap;
  uint8_t runnable_priority_bitmap;
  uint64_t admission_drops[4];
  uint16_t runnable_credit_count;
  uint8_t admission_profile_id;
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
  uint8_t quantum_autotune_enabled;
  uint32_t quantum_autotune_interval_ticks;
  uint32_t quantum_autotune_min_ticks;
  uint32_t quantum_autotune_max_ticks;
  uint64_t quantum_autotune_last_tick;
  uint64_t quantum_autotune_last_switch_total;
  uint64_t quantum_autotune_adjustments;
  uint8_t dispatch_strategy;
  uint8_t turbo_wait_weight;
  uint8_t turbo_priority_weight;
  uint8_t turbo_autotune_enabled;
  uint32_t turbo_autotune_interval_ticks;
  uint64_t turbo_autotune_last_tick;
  uint64_t turbo_autotune_adjustments;
  uint8_t turbo_candidate_cache_valid;
  uint8_t turbo_candidate_cache_budget;
  uint8_t turbo_candidate_cache_max_reuse;
  uint32_t turbo_candidate_cache_index;
  uint64_t turbo_candidate_cache_hits;
  uint64_t turbo_candidate_cache_misses;
  uint32_t turbo_last_pid;
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

typedef enum {
  AEGIS_SCHED_STRATEGY_ROUND_ROBIN = 0,
  AEGIS_SCHED_STRATEGY_TURBO = 1
} aegis_scheduler_dispatch_strategy_t;

typedef enum {
  AEGIS_SCHED_ADMISSION_PROFILE_CUSTOM = 0,
  AEGIS_SCHED_ADMISSION_PROFILE_MINIMAL = 1,
  AEGIS_SCHED_ADMISSION_PROFILE_DESKTOP = 2,
  AEGIS_SCHED_ADMISSION_PROFILE_SERVER = 3
} aegis_scheduler_admission_profile_t;

typedef enum {
  AEGIS_SYSCALL_CLASS_FS = 1,
  AEGIS_SYSCALL_CLASS_NET = 2,
  AEGIS_SYSCALL_CLASS_DEVICE = 3,
  AEGIS_SYSCALL_CLASS_PROCESS = 4,
  AEGIS_SYSCALL_CLASS_IPC = 5
} aegis_syscall_class_t;

typedef struct {
  uint32_t process_id;
  uint32_t granted_capabilities;
  uint8_t active;
} aegis_syscall_process_caps_t;

typedef struct {
  uint16_t syscall_id;
  uint8_t syscall_class;
  uint32_t required_capability;
  uint8_t policy_gate_required;
  uint8_t active;
} aegis_syscall_rule_t;

typedef struct {
  aegis_syscall_process_caps_t process_caps[AEGIS_SYSCALL_GATE_CAPACITY];
  aegis_syscall_rule_t rules[AEGIS_SYSCALL_RULE_CAPACITY];
  uint64_t allow_count;
  uint64_t deny_missing_rule_count;
  uint64_t deny_missing_process_count;
  uint64_t deny_missing_capability_count;
  uint64_t deny_policy_gate_count;
} aegis_syscall_gate_matrix_t;

typedef struct {
  uint32_t channel_id;
  uint32_t quota_bytes;
  uint32_t inflight_bytes;
  uint64_t accepted_messages;
  uint64_t dropped_messages;
  uint64_t backpressure_events;
  uint8_t active;
} aegis_ipc_channel_state_t;

typedef struct {
  aegis_ipc_channel_state_t channels[AEGIS_IPC_CHANNEL_CAPACITY];
  uint64_t total_accepted_messages;
  uint64_t total_dropped_messages;
  uint64_t total_backpressure_events;
} aegis_ipc_channel_table_t;

typedef enum {
  AEGIS_MEMORY_ZONE_KERNEL = 1,
  AEGIS_MEMORY_ZONE_USER = 2,
  AEGIS_MEMORY_ZONE_IO = 3,
  AEGIS_MEMORY_ZONE_CACHE = 4
} aegis_memory_zone_kind_t;

typedef struct {
  uint32_t zone_id;
  uint8_t zone_kind;
  uint64_t budget_bytes;
  uint64_t used_bytes;
  uint64_t high_watermark_bytes;
  uint64_t reclaim_target_bytes;
  uint64_t reclaim_attempts;
  uint64_t reclaim_successes;
  uint8_t reclaim_hook_enabled;
  uint8_t active;
} aegis_memory_zone_t;

typedef struct {
  aegis_memory_zone_t zones[AEGIS_MEMORY_ZONE_CAPACITY];
  uint64_t total_budget_bytes;
  uint64_t total_used_bytes;
  uint64_t denied_charges;
  uint64_t reclaim_events;
} aegis_memory_zone_table_t;

typedef enum {
  AEGIS_CHECKPOINT_REASON_MANUAL = 1,
  AEGIS_CHECKPOINT_REASON_PRE_UPDATE = 2,
  AEGIS_CHECKPOINT_REASON_PRE_MIGRATION = 3,
  AEGIS_CHECKPOINT_REASON_AUTOMATED_RECOVERY = 4
} aegis_process_checkpoint_reason_t;

typedef struct {
  uint32_t process_id;
  uint32_t namespace_id;
  uint32_t thread_count;
  uint64_t vm_bytes;
  uint32_t capability_mask;
  uint64_t policy_revision;
  uint64_t scheduler_tick;
  uint8_t active;
} aegis_process_runtime_state_t;

typedef struct {
  uint32_t process_id;
  uint64_t checkpoint_epoch;
  uint64_t captured_at_tick;
  uint8_t reason;
  uint8_t restore_count;
  uint8_t last_restore_status;
  uint8_t valid;
  char tag[AEGIS_PROCESS_CHECKPOINT_TAG_MAX];
  aegis_process_runtime_state_t state;
} aegis_process_checkpoint_entry_t;

typedef struct {
  aegis_process_runtime_state_t runtime_states[AEGIS_PROCESS_CHECKPOINT_CAPACITY];
  aegis_process_checkpoint_entry_t checkpoints[AEGIS_PROCESS_CHECKPOINT_CAPACITY];
  uint64_t next_epoch;
  uint64_t capture_count;
  uint64_t restore_count;
  uint64_t restore_failures;
} aegis_process_checkpoint_table_t;

typedef struct {
  uint64_t last_wallclock_epoch;
  uint64_t last_monotonic_tick;
  uint64_t drift_budget_ppm;
  uint64_t attestations_ok;
  uint64_t attestations_failed;
  uint64_t rollback_detected;
  uint64_t drift_violations;
  uint64_t nonce_replay_detected;
  uint32_t boot_id;
  char recent_nonces[8][AEGIS_TIME_ATTEST_NONCE_MAX + 1u];
  uint8_t recent_nonce_count;
  uint8_t recent_nonce_head;
  uint8_t initialized;
} aegis_secure_time_attestor_t;

typedef struct {
  uint32_t schema_version;
  uint32_t boot_id;
  uint64_t observed_wallclock_epoch;
  uint64_t observed_monotonic_tick;
  uint64_t expected_min_wallclock_epoch;
  uint64_t expected_max_wallclock_epoch;
  uint64_t drift_budget_ppm;
  uint8_t accepted;
  uint8_t nonce_size;
  char nonce[AEGIS_TIME_ATTEST_NONCE_MAX + 1u];
  char reason[96];
} aegis_secure_time_attestation_result_t;

typedef struct {
  uint32_t namespace_id;
  uint32_t parent_namespace_id;
  uint32_t member_count;
  uint32_t local_pid_counter;
  uint8_t active;
} aegis_namespace_entry_t;

typedef struct {
  uint32_t process_id;
  uint32_t namespace_id;
  uint32_t local_pid;
  uint8_t active;
} aegis_namespace_process_entry_t;

typedef struct {
  aegis_namespace_entry_t namespaces[AEGIS_NAMESPACE_CAPACITY];
  aegis_namespace_process_entry_t processes[AEGIS_NAMESPACE_PROCESS_CAPACITY];
  uint32_t next_namespace_id;
  size_t namespace_count;
  size_t process_count;
} aegis_namespace_table_t;

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
void aegis_scheduler_enable_quantum_autotune(aegis_scheduler_t *scheduler,
                                             uint8_t enabled,
                                             uint32_t interval_ticks,
                                             uint32_t min_ticks,
                                             uint32_t max_ticks);
int aegis_scheduler_quantum_autotune_state_json(const aegis_scheduler_t *scheduler,
                                                char *out,
                                                size_t out_size);
void aegis_scheduler_enable_turbo(aegis_scheduler_t *scheduler, uint8_t enabled);
void aegis_scheduler_set_turbo_weights(aegis_scheduler_t *scheduler,
                                       uint8_t wait_weight,
                                       uint8_t priority_weight);
void aegis_scheduler_enable_turbo_autotune(aegis_scheduler_t *scheduler,
                                           uint8_t enabled,
                                           uint32_t interval_ticks);
int aegis_scheduler_turbo_state_json(const aegis_scheduler_t *scheduler, char *out, size_t out_size);
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
int aegis_scheduler_set_admission_limit(aegis_scheduler_t *scheduler,
                                        uint8_t priority,
                                        uint8_t max_processes);
int aegis_scheduler_get_admission_limit(const aegis_scheduler_t *scheduler,
                                        uint8_t priority,
                                        uint8_t *max_processes);
int aegis_scheduler_admission_drop_count(const aegis_scheduler_t *scheduler,
                                         uint8_t priority,
                                         uint64_t *count);
int aegis_scheduler_admission_snapshot_json(const aegis_scheduler_t *scheduler,
                                            char *out,
                                            size_t out_size);
int aegis_scheduler_apply_admission_profile(aegis_scheduler_t *scheduler, uint8_t profile_id);
int aegis_scheduler_apply_admission_profile_name(aegis_scheduler_t *scheduler,
                                                 const char *profile_name);
int aegis_scheduler_current_admission_profile(const aegis_scheduler_t *scheduler,
                                              uint8_t *profile_id_out);
void aegis_namespace_table_init(aegis_namespace_table_t *table);
int aegis_namespace_create(aegis_namespace_table_t *table,
                           uint32_t parent_namespace_id,
                           uint32_t *namespace_id_out);
int aegis_namespace_destroy(aegis_namespace_table_t *table, uint32_t namespace_id);
int aegis_namespace_attach_process(aegis_namespace_table_t *table,
                                   uint32_t process_id,
                                   uint32_t namespace_id,
                                   uint32_t *local_pid_out);
int aegis_namespace_detach_process(aegis_namespace_table_t *table, uint32_t process_id);
int aegis_namespace_translate_local_to_global(const aegis_namespace_table_t *table,
                                              uint32_t namespace_id,
                                              uint32_t local_pid,
                                              uint32_t *process_id_out);
int aegis_namespace_translate_global_to_local(const aegis_namespace_table_t *table,
                                              uint32_t namespace_id,
                                              uint32_t process_id,
                                              uint32_t *local_pid_out);
int aegis_namespace_can_inspect(const aegis_namespace_table_t *table,
                                uint32_t requester_process_id,
                                uint32_t target_process_id,
                                uint8_t *allowed_out);
int aegis_namespace_snapshot_json(const aegis_namespace_table_t *table,
                                  char *out,
                                  size_t out_size);
void aegis_syscall_gate_matrix_init(aegis_syscall_gate_matrix_t *matrix);
int aegis_syscall_gate_set_process_caps(aegis_syscall_gate_matrix_t *matrix,
                                        uint32_t process_id,
                                        uint32_t granted_capabilities);
int aegis_syscall_gate_remove_process(aegis_syscall_gate_matrix_t *matrix, uint32_t process_id);
int aegis_syscall_gate_set_rule(aegis_syscall_gate_matrix_t *matrix,
                                uint16_t syscall_id,
                                uint8_t syscall_class,
                                uint32_t required_capability,
                                uint8_t policy_gate_required);
int aegis_syscall_gate_check(aegis_syscall_gate_matrix_t *matrix,
                             uint32_t process_id,
                             uint16_t syscall_id,
                             uint8_t policy_gate_allowed,
                             uint8_t *allowed_out);
int aegis_syscall_gate_snapshot_json(const aegis_syscall_gate_matrix_t *matrix,
                                     char *out,
                                     size_t out_size);
void aegis_ipc_channel_table_init(aegis_ipc_channel_table_t *table);
int aegis_ipc_channel_configure(aegis_ipc_channel_table_t *table,
                                uint32_t channel_id,
                                uint32_t quota_bytes);
int aegis_ipc_channel_reserve_send(aegis_ipc_channel_table_t *table,
                                   uint32_t channel_id,
                                   uint32_t payload_bytes,
                                   uint8_t *accepted_out);
int aegis_ipc_channel_drain(aegis_ipc_channel_table_t *table,
                            uint32_t channel_id,
                            uint32_t drained_bytes);
int aegis_ipc_channel_snapshot_json(const aegis_ipc_channel_table_t *table,
                                    char *out,
                                    size_t out_size);
void aegis_memory_zone_table_init(aegis_memory_zone_table_t *table);
int aegis_memory_zone_configure(aegis_memory_zone_table_t *table,
                                uint32_t zone_id,
                                uint8_t zone_kind,
                                uint64_t budget_bytes);
int aegis_memory_zone_set_reclaim_hook(aegis_memory_zone_table_t *table,
                                       uint32_t zone_id,
                                       uint8_t enabled,
                                       uint64_t reclaim_target_bytes);
int aegis_memory_zone_charge(aegis_memory_zone_table_t *table,
                             uint32_t zone_id,
                             uint64_t bytes,
                             uint8_t *accepted_out);
int aegis_memory_zone_release(aegis_memory_zone_table_t *table,
                              uint32_t zone_id,
                              uint64_t bytes);
int aegis_memory_zone_snapshot_json(const aegis_memory_zone_table_t *table,
                                    char *out,
                                    size_t out_size);
void aegis_process_checkpoint_table_init(aegis_process_checkpoint_table_t *table);
int aegis_process_checkpoint_register_runtime(aegis_process_checkpoint_table_t *table,
                                              const aegis_process_runtime_state_t *state);
int aegis_process_checkpoint_capture(aegis_process_checkpoint_table_t *table,
                                     uint32_t process_id,
                                     uint8_t reason,
                                     uint64_t captured_at_tick,
                                     const char *tag,
                                     uint64_t *checkpoint_epoch_out);
int aegis_process_checkpoint_restore(aegis_process_checkpoint_table_t *table,
                                     uint32_t process_id,
                                     uint64_t expected_epoch,
                                     aegis_process_runtime_state_t *restored_state_out);
int aegis_process_checkpoint_query(const aegis_process_checkpoint_table_t *table,
                                   uint32_t process_id,
                                   aegis_process_checkpoint_entry_t *entry_out);
int aegis_process_checkpoint_snapshot_json(const aegis_process_checkpoint_table_t *table,
                                          char *out,
                                          size_t out_size);
int aegis_process_checkpoint_journal_save(const aegis_process_checkpoint_table_t *table,
                                          const char *journal_path);
int aegis_process_checkpoint_journal_replay(aegis_process_checkpoint_table_t *table,
                                            const char *journal_path,
                                            uint8_t apply_runtime_states);
void aegis_secure_time_attestor_init(aegis_secure_time_attestor_t *attestor,
                                     uint32_t boot_id,
                                     uint64_t baseline_wallclock_epoch,
                                     uint64_t baseline_monotonic_tick,
                                     uint64_t drift_budget_ppm);
int aegis_secure_time_attest(aegis_secure_time_attestor_t *attestor,
                             uint64_t observed_wallclock_epoch,
                             uint64_t observed_monotonic_tick,
                             const char *nonce,
                             aegis_secure_time_attestation_result_t *result_out);
int aegis_secure_time_attestation_json(const aegis_secure_time_attestation_result_t *result,
                                       char *out,
                                       size_t out_size);
int aegis_secure_time_attestor_snapshot_json(const aegis_secure_time_attestor_t *attestor,
                                             char *out,
                                             size_t out_size);

#endif
