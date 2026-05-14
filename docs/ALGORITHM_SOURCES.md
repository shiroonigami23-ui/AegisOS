# Algorithm Sources (Wiki)

This project's algorithm-lab baseline draws from wiki references for practical kernel-oriented choices:

- Hash table concepts: https://en.wikipedia.org/wiki/Hash_table
- Open addressing: https://en.wikipedia.org/wiki/Open_addressing
- Round-robin scheduling: https://en.wikipedia.org/wiki/Round-robin_scheduling
- Bit array / bitmap operations: https://en.wikipedia.org/wiki/Bit_array

How this maps to AegisOS:
- Namespace global PID lookup: hash-bucket chain style index to reduce O(n) scans.
- Ready-class selection: bitmap/bit-scan style winner selection in scheduler hot path.
- Fairness baseline: keep round-robin-compatible behavior for predictability.
