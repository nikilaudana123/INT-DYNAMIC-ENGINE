Markdown# INT Dynamic Engine (`v3.0.0`)

**A lightweight, C++17-powered, AES-256-GCM encrypted out-of-core storage, caching, and analytics engine built to eliminate Out-Of-Memory (OOM) spikes on low-RAM servers.**

Designed and architected by **Nikila Udana ([INTTECH Sri Lanka](https://inttech.lk))**, `int-dynamic-engine` replaces heavy background daemons (such as Redis) with a single in-process **C++17 shared library (`libinte.so`)** accessible via native FFI across **Python, Node.js, and PHP**.

---

## Key Features

- **Strict RAM Arena + Automatic Disk Spillover:** Enforce a hard RAM cap (e.g., `16 MB`). Hot keys remain in C++ memory for microsecond reads, while excess data automatically spills to disk without crashing your application.
- **Native AES-256-GCM Encryption:** Every spilled record is encrypted at rest using OpenSSL `AES-256-GCM` with SHA-256 derived 32-byte keys.
- **Zero-Daemon Polyglot Architecture:** Compiles into a lightweight C-ABI shared library (`libinte.so`)—eliminating background server processes and TCP socket overhead.
- **On-Demand Disk Compaction (`compact`):** Reclaims fragmented dead disk space caused by overwritten or deleted keys.
- **Out-of-Core OLAP Pushdown:** Execute prefix scans (`scan_prefix`) and C++ aggregation pushdowns (`aggregate_double_prefix` for `count`, `sum`, `avg`, `min`, `max`) directly over cold disk records without loading them into Python or Node.js RAM.

---

## Prerequisites (Linux / Ubuntu)

Because `int-dynamic-engine` compiles its native C++17 core automatically on first import (or via `install.sh`), ensure `g++` and OpenSSL development headers are installed:

```bash
sudo apt update && sudo apt install -y g++ libssl-dev
InstallationPython (PyPI)Bashpip install --upgrade int-dynamic-engine
System-Wide C++ Shared Library (For Node.js, PHP & C/C++)Bashsudo bash install.sh
This installs /usr/local/lib/libinte.so, /usr/local/include/inte_core.h, and language bindings under /opt/int-dynamic-engine/bindings/.Quick Start (Python)Pythonimport json
from inte import IntDynamicEngine

# Initialize engine with a strict 16 MB RAM cap
db = IntDynamicEngine(
    storage_dir="./my_encrypted_vault",
    max_ram_mb=16.0,
    secret_key="your-master-secret-key"
)

# Store raw bytes or UTF-8 strings
db.put("status", b"Production Active")
db.put("user:101", json.dumps({"name": "Nikila", "role": "Architect"}))

# Retrieve & auto-decrypt (works seamlessly across RAM and disk spillover)
print(db.get("status").decode("utf-8"))
print(json.loads(db.get("user:101").decode("utf-8")))

# Inspect live memory & disk telemetry
print("Engine Stats:", db.stats())
print("Disk Stats:", db.disk_stats())

# Reclaim fragmented disk space & safely flush index on exit
db.compact()
db.close()
Python API ReferenceMethodDescriptionIntDynamicEngine(storage_dir, max_ram_mb, secret_key, lib_path=None)Initializes the C++17 engine and recovers persistent disk indexes if present.put(key: str, data: bytes | str)Encrypts and stores data under key, spilling cold items to disk when max_ram_mb is reached.get(key: str) -> bytes | NoneRetrieves and decrypts data from RAM or cold disk storage (None if missing).delete(key: str) -> boolRemoves a key from active RAM and the disk index.stats() -> dictReturns ram_used_kb, ram_items, and disk_items.disk_stats() -> dictReturns active_kb, file_size_kb, and dead_space_kb.compact()Compacts the encrypted disk log to reclaim dead space from deleted or updated keys.scan_prefix(prefix, callback, contains_filter=None)Streams matching records directly from disk without polluting hot RAM.aggregate_double_prefix(prefix, value_offset=0)Computes count, sum, avg, min, and max over little-endian float64 payloads in C++.close()Flushes indexes to disk and releases C++ heap memory cleanly.Multi-Language Usage (Node.js & PHP)When installed system-wide via install.sh, the same C++ core (libinte.so) can be imported directly in Node.js (koffi) and PHP (FFI):Node.jsJavaScriptconst { IntDynamicEngine } = require('/opt/int-dynamic-engine/bindings/node/inte.js');

const db = new IntDynamicEngine('/var/lib/int-engine/app', 16, 'your-master-secret-key');
db.put('session:1', JSON.stringify({ user: 'Nikila', active: true }));
console.log(db.get('session:1').toString('utf8'));
console.log(db.stats());
db.close();
License & AuthorAuthor: Nikila Udana (INTTECH Sri Lanka)Contact: intxteam@gmail.comLicense: MIT License
