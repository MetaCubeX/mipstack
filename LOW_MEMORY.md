# Low-memory TCP storage

Build with the existing `with_low_memory` tag to select smaller TCP storage
and cache bounds. No runtime setter or additional feature tag is required.
Ordinary builds retain the existing values and behavior.

| Storage policy | Ordinary build | `with_low_memory` |
| --- | ---: | ---: |
| Minimum first send allocation | 2 KiB | 1 KiB |
| Largest reusable acknowledged send chunk | 32 KiB | 16 KiB |
| Retained drained receive metadata | 64 slice slots | 32 slice slots |

Allocation remains demand-driven. The first send allocation can exceed its
minimum when the application writes more data. Repeated moderate writes still
reuse one eligible acknowledged chunk; common-MTU receive payloads and short
metadata arrays remain reusable. Larger unused backing is released after it
drains. Unread or unacknowledged bytes are never truncated.

An undersized small spare is not reused for a larger first write in the
low-memory build. For example, a one-byte write can leave a 1 KiB spare. A
subsequent 1,200-byte write gets one fitted allocation, instead of filling the
small spare and allocating another 16 KiB chunk for its tail. Later chunks
retain their existing minimum so packet scatter bounds remain valid.

This changes storage retention, not TCP flow control. Default buffer limits,
automatic receive/send growth, advertised windows, retransmission handling,
and explicit socket options keep their existing behavior. The package adds
no pressure polling, timer, callback, forced GC, or per-connection state.
It does not provide a whole-stack or whole-process memory cap.

## iOS motivation

Hako already builds its iOS/tvOS core slices with `with_low_memory`; its macOS
slice does not use that tag. Hako's iOS extension targets a 50 MiB engineering
budget. Its gVisor TCP profile uses 32 KiB initial and 128 KiB maximum buffers
in each direction. The tests also express those byte limits as MIPS options;
this is a comparison workload, not a claim that the two stacks have identical
semantics. Smaller configured maxima alone do not release idle caches.

## Validation

Run the root test/race and vet suites with and without `with_low_memory`.
The gVisor interoperability tests are a separate module in `interop/gvisor`.
`TestLowMemory*` covers cache bounds, useful reuse, payload preservation, and
the tiny-write-to-larger-write allocation edge case. Existing transport tests
continue to exercise the normal flow-control and lifecycle paths.

`TestTCPMemoryProfileBaseline` accounts for retained backing in a deterministic
1,000-connection fixture. It excludes live actors, connection structs, runtime
memory and physical footprint. Stream benchmarks transfer packets between two
in-process stacks; their throughput is not Internet speed or device energy.
Physical-device measurements must separately report their process type,
workload, compiler, memory, throughput, latency, CPU cost and limitations.

### Latest host review

On Go 1.26.5 darwin/arm64, the root race suite and vet passed for both
ordinary and low-memory builds. The full gVisor interoperability suite also
passed for both builds in serial, non-race runs with GOMAXPROCS=2.

Running both complete gVisor race suites concurrently with GOMAXPROCS=4
produced timeouts in IPv4 MTU-68 and some custom-congestion-control cases;
both suites eventually reached their three-minute timeout. This is an
unresolved validation limitation, not a passing race result. Similar MTU-68
instability was previously observed on the unmodified baseline. These results
do not establish the cause or attribute it to this change, and this patch
does not claim to fix it.

## Physical iPad comparison

An iPad Pro (12.9-inch, 6th generation; iPad14,5) running iPadOS 26.6.2 ran
three fresh-process repetitions per build, with baseline/candidate order
alternated. Both builds used Go 1.26.5, `with_low_memory`, and GOMAXPROCS=2.
The baseline MIPS commit was `ba762df4c91d6f9bddf82062afb0d40aa1352687`, which
does not act on that tag. No runtime pressure API was present or called.

The independent Debug App connected two MIPS stacks through an in-process
packet link, using 256 connection pairs and the Hako 32/128 KiB socket profile.
Each connection exchanged a one-byte message, two 1,200-byte messages, and
three 32 KiB messages. Idle measurements followed a 500 ms pause and explicit
GC in both builds. One connection then ran 1,000 small request/response cycles
and a fixed 1 GiB bidirectional payload transfer. Every connection was checked
again after the stream. All six runs completed without transfer errors.

| Measurement (median of three runs) | Baseline | Low-memory candidate |
| --- | ---: | ---: |
| Live Go heap after small messages | 4.68 MiB | 4.31 MiB |
| Live Go heap after repeated 32 KiB messages | 16.19 MiB | 8.08 MiB |
| Process physical footprint at that latter boundary | 51.74 MiB | 40.19 MiB |
| Fixed-byte stream throughput, both directions combined | 2.61 Gbps | 2.71 Gbps |
| Stream process CPU cost | 2.324 CPU seconds/GB | 2.418 CPU seconds/GB |
| Stream allocation traffic per payload byte | 2.123 B/B | 2.207 B/B |
| Small-request p95 round-trip latency | 47.67 microseconds | 43.29 microseconds |
| Highest sampled process footprint | 66.53 MiB | 49.50 MiB |

Throughput uses decimal Gbps (10^9 bits/s) and counts both echoed payload
directions. For this symmetric echo workload, each direction therefore
accounts for approximately 1.31 and 1.35 Gbps, respectively. These are not
separate upload/download saturation tests and cannot be compared directly
with one-way benchmark charts.

The 32 KiB workload deliberately exercises backing that the ordinary build
retains and the low-memory build releases. Its roughly 8.11 MiB live-heap
saving across 512 TCP endpoints is workload-specific. Small messages saved
about 0.38 MiB; idle savings do not scale from connection count alone.
The stream showed no large throughput collapse in these runs, but its small
throughput/latency differences are not proof of a speed improvement. CPU cost
and allocation traffic per byte increased by about 4%. Applications dominated
by repeated medium-sized writes may pay more allocation cost and should test
that workload separately.

These are standalone App process results, not NetworkExtension, PacketFlow,
Internet throughput, battery, or iOS termination-risk measurements. The probe
contains both TCP endpoints. Its footprint cannot be interpreted as Hako's
extension footprint or compared directly with the 50 MiB engineering budget.
The 100 ms footprint sampler may miss shorter peaks. The API does not force
GC; explicit GC is used only by the measurement harness.

## Ordinary build boundary

On Go 1.26.5 darwin/arm64, fifteen affected ordinary-build functions matched
baseline instructions after address relocation normalization, including the
send-buffer append/acknowledgement paths, TCP read path, established loop and
handshakes. No connection or stack fields are added. This check is specific
to that compiler and architecture; it is not whole-binary identity or a claim
that every platform has been benchmarked.
