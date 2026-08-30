# Copy-Fail Vulnerability (CVE-2026-31431)

## Executive Summary
Copy-Fail (CVE-2026-31431) is a local privilege escalation exploit that upgrades any user to root using an unauthenticated page cache write in Linux’s Crypto API...[cite: 2]

## Diagram and Visual Flow

## Technical Analysis: Zero-Copy Pipelines & `splice()`
The vulnerability stems from how the Linux Crypto API's socket interface (`algif_aead`) handles zero-copy memory transfers via the `splice()` system call...

## Root Cause Analysis (Memory & Crypto API Failure)
When `splice()` feeds data into an `authencesn` cryptographic transformation, the destination Page Cache page is mapped and modified before authentication tag validation completes...

## High-Level Proof of Concept (PoC)
1. Open a read-only file descriptor pointing to a setuid executable (e.g., `/usr/bin/su`) to populate the kernel page cache.[cite: 2]
2. Construct a pipe and set up an `AF_ALG` socket configured with `authencesn`.[cite: 2]
3. Issue a `splice()` system call to move page references in the Crypto API pipeline, triggering a partial-write error.[cite: 2]
4. Verify the 4-bytes in the executable have been overwritten without affecting the overall executable file’s structure on disk.[cite: 2]
5. Execute the modified binary to spawn an unauthenticated root shell.[cite: 2]

## Threat Model Relevance: Multi-Tenant & AI Sandboxes
While local privilege escalation vulnerabilities are traditionally evaluated against multi-user enterprise Linux servers, zero-copy memory corruption presents unique hazards for AI infrastructure and model evaluation environments:
* **Container & Sandbox Escape:** Frontier AI labs run untrusted model-generated code, agentic tool outputs, and user-submitted code snippets inside lightweight Linux containers or microVMs. A zero-copy page cache corruption bypasses container rootless boundaries by targeting shared host page frames.
* **Persistent In-Memory Tampering:** Because the 4-byte overwrite modifies active Page Cache memory without altering disk binaries, traditional file-integrity monitoring tools fail to flag the alteration, allowing stealthy execution alteration in shared execution environments.

## Detection & Behavioral Indicators
Complete auditing of `splice()` system calls into `AF_ALG` sockets when communicating with read-only cache pages. Track abnormal module errors or socket panics in `dmesg` associated with `algif_aead`.

## Mitigation
Update kernels to the latest version and ensure proper dirty page invalidation on cryptographic transformation failures.
