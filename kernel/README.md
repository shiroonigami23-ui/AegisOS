# kernel

Kernel direction, interfaces, and implementation notes live here.

## Current Modules

- `aegis_scheduler_t`: weighted round-robin scheduler with priority-aware dispatch.
  - includes dispatch metrics: total dispatches, high-watermark queue depth, and per-process counts.
