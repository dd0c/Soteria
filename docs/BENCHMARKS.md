# Benchmarks

Measured with the benchmark example (SRS 12.4):

```sh
cargo run --release -p soteria-agent --example bench -- [files] [changes] [executions]
```

It builds a synthetic tree in a temporary directory (mostly 2 KiB files,
some 64 KiB and 1 MiB ones), then measures a full scan, a signed baseline,
and the running agent with the real inotify sensor. Executions are fed in
directly (auditd is not involved) and committed in batches, as the sensor
path does. Results are printed as the table below.

## Results

Defaults (50,000 files, 1,000 changes, 5,000 executions), release build,
2026-11-21. Environment: 4 vCPU Intel Xeon @ 2.10 GHz virtual machine,
15 GiB RAM, virtio disk, Linux 6.18; the database uses SQLite's rollback
journal with `synchronous=FULL`, so every commit waits for the disk.

| Measure | Result | Requirement |
|---|---|---|
| Full scan of 50,201 objects (1,398 MiB) | 1,819 ms (27,602 objects/s, 1,763 ms CPU) | NFR-003 |
| Database size after baseline | 26.2 MiB (about 550 bytes per object) | |
| Idle agent CPU | 0.09 % | NFR-001: below 1 % |
| Single change to alert (median / max of 20) | 301 ms / 316 ms | NFR-004: within 2 s |
| Burst of 1,000 changes (written in 24 ms) to all alerts | 655 ms (1,000 alerts) | NFR-004 |
| Execution events handled | 6,535 per second | NFR-005 |
| Peak memory (whole process) | 12 MiB | NFR-002: below 150 MB |

Notes:

- Most of the single-change latency is deliberate: a file is verified once
  its events have been quiet for 250 ms (at most 1.5 s after the first
  event), so a file being written is not hashed half way through.
- Before this release a burst of 1,000 changes took 4.0 s to reach the last
  alert, because each file was committed on its own. Settled files are now
  verified in one transaction.
- The scan was CPU bound (hashing) with a warm page cache. On a cold cache it
  is bounded by disk reads.
- Peak memory is for the whole benchmark process, including the scan and the
  agent; the daemon alone is smaller.
- Queue overload (NFR-006) is covered by tests: a full queue or a kernel
  queue overflow raises a coverage gap and schedules a reconciliation scan.

## Running on your own hardware

Run the command above on a host like the ones you will monitor, with the
temporary directory (`TMPDIR`) on a representative disk. Numbers on
physical servers with local SSDs are usually better than the virtual
machine above.
