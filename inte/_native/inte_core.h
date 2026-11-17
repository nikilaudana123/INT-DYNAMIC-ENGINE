#ifndef INTE_CORE_H
#define INTE_CORE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Engine handle
typedef void* InteHandle;

// Initialize engine with storage directory, max RAM in bytes, and 32-byte AES-256 key
InteHandle inte_init(const char* storage_dir, size_t max_ram_bytes, const uint8_t* aes_key_32);

// Store binary/string data under key (returns 0 on success, <0 on error)
int inte_put(InteHandle handle, const char* key, const uint8_t* data, size_t len);

// Retrieve data (allocates buffer via malloc; caller must free using inte_free_buf)
int inte_get(InteHandle handle, const char* key, uint8_t** out_data, size_t* out_len);

// Free buffer returned by inte_get
void inte_free_buf(uint8_t* buf);

// Delete a key from RAM and Index
int inte_delete(InteHandle handle, const char* key);

// Get current RAM usage and total keys count
void inte_stats(InteHandle handle, size_t* out_ram_used, size_t* out_ram_items, size_t* out_disk_items);

// Flush index to disk and clean up memory
void inte_close(InteHandle handle);

// Get active encrypted bytes vs actual physical file size on disk
void inte_disk_stats(InteHandle handle, size_t* out_active_bytes, size_t* out_file_bytes);

// Reclaim dead disk space from overwritten/deleted keys (returns 0 on success, <0 on error)
int inte_compact(InteHandle handle);

// Callback for streaming prefix scan (return 0 to continue, non-zero to stop early)
typedef int (*InteScanCallback)(const char* key, const uint8_t* data, size_t len, void* user_data);

// Stream records matching key prefix (and optional substring filter) without polluting hot RAM
int inte_scan_prefix(InteHandle handle, const char* prefix, const char* contains_filter,
                     InteScanCallback cb, void* user_data);

// Out-of-core C++ aggregation pushdown over little-endian float64 (double) at byte offset
int inte_aggregate_double_prefix(InteHandle handle, const char* prefix, size_t value_offset,
                                 size_t* out_count, double* out_sum, double* out_min, double* out_max);

#ifdef __cplusplus
}
#endif

#endif // INTE_CORE_H