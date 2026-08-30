# Copy-Fail Vulnerability (CVE-2026-31431)

## Executive Summary
Copy-Fail (CVE-2026-31431) is a local privilege escalation exploit that upgrades any user to root using an unauthenticated page cache write in Linux’s Crypto API. An attacker can inject executable code via 4-byte writes in the page cache, escalating privileges to root. To do this, the vulnerability exploits the `authencesn` algorithmic template chained through the `AF_ALG` socket-based interface and uses the `splice()` system call to write 4 bytes into the page cache. The exploit has affected almost every Linux distribution since 2017 and requires minimal tooling to execute, potentially exposing a wide range of Linux systems to a serious vulnerability. Common mitigations include upgrading the user’s Linux distribution, and system administrators managing Linux systems are highly advised to check for affected kernels (https://copy.fail/#affected).

## Diagram and Visual Flow
<img width="800" height="600" alt="image" src="https://github.com/user-attachments/assets/df669aee-3f80-459e-8334-2d8d13b5a96d" />

## Technical Analysis: Zero-Copy Pipelines & `splice()`
The vulnerability stems from how the Linux Crypto API's socket interface (`algif_aead`) handles zero-copy memory transfers via the `splice()` system call. To optimize performance, zero-copy pipelines stream data by passing page references directly between pipe buffers and kernel scatterlists without staging data in intermediate CPU-allocated buffers.

## Root Cause Analysis (Memory & Crypto API Failure)
When `splice()` feeds data into an authencesn cryptographic transformation, the destination Page Cache page is mapped and modified before authentication tag validation completes. If the transformation fails mid-stream, triggering a partial write error, `algif_aead` fails to unwind or invalidate the mutated page frame. Because zero-copy operations bypass standard copy-on-write (COW) protection, the unauthenticated 4-byte overwrite remains permanently resident in the active kernel Page Cache, enabling local privilege escalation without modifying the underlying disk binary.

## High-Level Proof of Concept (PoC)
1. Open a read-only file descriptor pointing to a setuid executable (i.e., `/usr/bin/su`) to populate the kernel page cache.
2. Construct a pipe and set up an `AF_ALG` socket configured with `authencesn`.
3. Issue a `splice()` system call to move page references in the Crypto API pipeline, triggering a partial-write error.
4. Verify the 4-bytes in the executable have been overwritten without affecting the overall executable file’s structure on disk.
5. Execute the modified binary to spawn an unauthenticated root shell.

## Threat Model Relevance: Multi-Tenant & AI Sandboxes
While local privilege escalation vulnerabilities are traditionally evaluated against multi-user enterprise Linux servers, zero-copy memory corruption presents unique hazards for AI infrastructure and model evaluation environments:
* **Container & Sandbox Escape:** Frontier AI labs run untrusted model-generated code, agentic tool outputs, and user-submitted code snippets inside lightweight Linux containers or microVMs. A zero-copy page cache corruption bypasses container rootless boundaries by targeting shared host page frames.
* **Persistent In-Memory Tampering:** Because the 4-byte overwrite modifies active Page Cache memory without altering disk binaries, traditional file-integrity monitoring tools fail to flag the alteration, allowing stealthy execution alteration in shared execution environments.

## Detection & Behavioral Indicators
Complete auditing of `splice()` system calls into `AF_ALG` sockets when communicating with read-only cache pages. Track abnormal module errors or socket panics in `dmesg` associated with `algif_aead`.

## Mitigation
Update kernels to the latest version and ensure proper dirty page invalidation on cryptographic transformation failures.
