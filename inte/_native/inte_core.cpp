#include <algorithm>
#include <limits>
#include "inte_core.h"
#include <unordered_map>
#include <list>
#include <vector>
#include <string>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <mutex>
#include <filesystem>
#include <openssl/evp.h>
#include <openssl/rand.h>

#ifdef __linux__
#include <malloc.h>
#endif

namespace fs = std::filesystem;

struct DiskEntry {
    uint64_t offset;
    uint32_t cipher_len;
    uint8_t iv[12];
    uint8_t tag[16];
};

struct RamNode {
    std::string key;
    std::vector<uint8_t> data;
};

struct InteEngine {
    std::string storage_dir;
    std::string data_path;
    std::string index_path;
    size_t max_ram_bytes;
    size_t current_ram_bytes = 0;
    uint8_t key[32];

    std::mutex mtx;
    std::list<RamNode> lru_list;
    std::unordered_map<std::string, std::list<RamNode>::iterator> ram_map;
    std::unordered_map<std::string, DiskEntry> disk_map;
};

// AES-256-GCM Encrypt
static bool aes_gcm_encrypt(const uint8_t* key, const std::vector<uint8_t>& plain,
                            std::vector<uint8_t>& cipher, uint8_t iv[12], uint8_t tag[16]) {
    if (RAND_bytes(iv, 12) != 1) return false;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    cipher.resize(plain.size());
    int len = 0, total_len = 0;

    bool ok = (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1) &&
              (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1) &&
              (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv) == 1) &&
              (EVP_EncryptUpdate(ctx, cipher.data(), &len, plain.data(), static_cast<int>(plain.size())) == 1);

    total_len = len;
    if (ok && EVP_EncryptFinal_ex(ctx, cipher.data() + total_len, &len) == 1) {
        total_len += len;
        cipher.resize(total_len);
        ok = (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) == 1);
    } else {
        ok = false;
    }

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

// AES-256-GCM Decrypt
static bool aes_gcm_decrypt(const uint8_t* key, const std::vector<uint8_t>& cipher,
                            const uint8_t iv[12], const uint8_t tag[16], std::vector<uint8_t>& plain) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    plain.resize(cipher.size());
    int len = 0, total_len = 0;

    bool ok = (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1) &&
              (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1) &&
              (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv) == 1) &&
              (EVP_DecryptUpdate(ctx, plain.data(), &len, cipher.data(), static_cast<int>(cipher.size())) == 1);

    total_len = len;
    if (ok) {
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8_t*>(tag));
        if (EVP_DecryptFinal_ex(ctx, plain.data() + total_len, &len) == 1) {
            total_len += len;
            plain.resize(total_len);
        } else {
            ok = false; // Authentication failed (tampered data or wrong key)
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

// Offload single entry to encrypted disk store
static bool offload_to_disk(InteEngine* eng, const std::string& k, const std::vector<uint8_t>& data) {
    std::vector<uint8_t> cipher;
    DiskEntry entry{};
    if (!aes_gcm_encrypt(eng->key, data, cipher, entry.iv, entry.tag)) return false;

    std::ofstream out(eng->data_path, std::ios::binary | std::ios::app);
    if (!out.is_open()) return false;

    out.seekp(0, std::ios::end);
    entry.offset = static_cast<uint64_t>(out.tellp());
    entry.cipher_len = static_cast<uint32_t>(cipher.size());
    out.write(reinterpret_cast<const char*>(cipher.data()), cipher.size());
    out.close();

    eng->disk_map[k] = entry;
    return true;
}

// Enforce RAM limit via LRU eviction
static void enforce_ram_limit(InteEngine* eng) {
    bool evicted = false;
    while (eng->current_ram_bytes > eng->max_ram_bytes && !eng->lru_list.empty()) {
        auto last_it = std::prev(eng->lru_list.end());
        if (offload_to_disk(eng, last_it->key, last_it->data)) {
            eng->current_ram_bytes -= (last_it->data.size() + last_it->key.size());
            eng->ram_map.erase(last_it->key);
            eng->lru_list.erase(last_it);
            evicted = true;
        } else {
            break;
        }
    }
#ifdef __linux__
    if (evicted) {
        malloc_trim(0); // Return freed heap pages immediately to Linux kernel
    }
#endif
}

// Save binary persistent index
static void save_index(InteEngine* eng) {
    std::ofstream out(eng->index_path, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) return;

    uint32_t count = static_cast<uint32_t>(eng->disk_map.size());
    out.write(reinterpret_cast<const char*>(&count), sizeof(count));

    for (const auto& [k, entry] : eng->disk_map) {
        uint32_t klen = static_cast<uint32_t>(k.size());
        out.write(reinterpret_cast<const char*>(&klen), sizeof(klen));
        out.write(k.data(), klen);
        out.write(reinterpret_cast<const char*>(&entry.offset), sizeof(entry.offset));
        out.write(reinterpret_cast<const char*>(&entry.cipher_len), sizeof(entry.cipher_len));
        out.write(reinterpret_cast<const char*>(entry.iv), 12);
        out.write(reinterpret_cast<const char*>(entry.tag), 16);
    }
}

// Load binary persistent index on startup
static void load_index(InteEngine* eng) {
    std::ifstream in(eng->index_path, std::ios::binary);
    if (!in.is_open()) return;

    uint32_t count = 0;
    if (!in.read(reinterpret_cast<char*>(&count), sizeof(count))) return;

    for (uint32_t i = 0; i < count; ++i) {
        uint32_t klen = 0;
        if (!in.read(reinterpret_cast<char*>(&klen), sizeof(klen))) break;
        std::string k(klen, '\0');
        in.read(&k[0], klen);

        DiskEntry entry{};
        in.read(reinterpret_cast<char*>(&entry.offset), sizeof(entry.offset));
        in.read(reinterpret_cast<char*>(&entry.cipher_len), sizeof(entry.cipher_len));
        in.read(reinterpret_cast<char*>(entry.iv), 12);
        in.read(reinterpret_cast<char*>(entry.tag), 16);

        eng->disk_map[k] = entry;
    }
}

extern "C" {

InteHandle inte_init(const char* storage_dir, size_t max_ram_bytes, const uint8_t* aes_key_32) {
    if (!storage_dir || !aes_key_32) return nullptr;

    auto* eng = new InteEngine();
    eng->storage_dir = storage_dir;
    eng->max_ram_bytes = max_ram_bytes;
    std::memcpy(eng->key, aes_key_32, 32);

    fs::create_directories(eng->storage_dir);
    eng->data_path = (fs::path(eng->storage_dir) / "inte_store.dat").string();
    eng->index_path = (fs::path(eng->storage_dir) / "inte_index.idx").string();

    load_index(eng);
    return static_cast<InteHandle>(eng);
}

int inte_put(InteHandle handle, const char* key, const uint8_t* data, size_t len) {
    if (!handle || !key || (!data && len > 0)) return -1;
    auto* eng = static_cast<InteEngine*>(handle);
    std::lock_guard<std::mutex> lock(eng->mtx);

    std::string k(key);
    std::vector<uint8_t> vec(data, data + len);

    // Remove existing RAM entry if updating
    auto rit = eng->ram_map.find(k);
    if (rit != eng->ram_map.end()) {
        eng->current_ram_bytes -= (rit->second->data.size() + rit->second->key.size());
        eng->lru_list.erase(rit->second);
        eng->ram_map.erase(rit);
    }
    // Remove stale disk entry if updating
    eng->disk_map.erase(k);

    // If single item is larger than entire RAM cap, write straight to encrypted disk
    if (vec.size() + k.size() > eng->max_ram_bytes) {
        return offload_to_disk(eng, k, vec) ? 0 : -2;
    }

    eng->lru_list.push_front(RamNode{k, std::move(vec)});
    eng->ram_map[k] = eng->lru_list.begin();
    eng->current_ram_bytes += (eng->lru_list.front().data.size() + k.size());

    enforce_ram_limit(eng);
    return 0;
}

int inte_get(InteHandle handle, const char* key, uint8_t** out_data, size_t* out_len) {
    if (!handle || !key || !out_data || !out_len) return -1;
    auto* eng = static_cast<InteEngine*>(handle);
    std::lock_guard<std::mutex> lock(eng->mtx);

    std::string k(key);

    // 1. Check RAM (Hot Tier)
    auto rit = eng->ram_map.find(k);
    if (rit != eng->ram_map.end()) {
        eng->lru_list.splice(eng->lru_list.begin(), eng->lru_list, rit->second);
        const auto& vec = rit->second->data;
        *out_len = vec.size();
        *out_data = static_cast<uint8_t*>(std::malloc(vec.size() > 0 ? vec.size() : 1));
        if (!vec.empty()) std::memcpy(*out_data, vec.data(), vec.size());
        return 0;
    }

    // 2. Check Encrypted Disk (Cold Tier)
    auto dit = eng->disk_map.find(k);
    if (dit != eng->disk_map.end()) {
        const DiskEntry& entry = dit->second;
        std::ifstream in(eng->data_path, std::ios::binary);
        if (!in.is_open()) return -2;

        in.seekg(entry.offset);
        std::vector<uint8_t> cipher(entry.cipher_len);
        in.read(reinterpret_cast<char*>(cipher.data()), entry.cipher_len);

        std::vector<uint8_t> plain;
        if (!aes_gcm_decrypt(eng->key, cipher, entry.iv, entry.tag, plain)) {
            return -3; // Decryption / Integrity check failed
        }

        *out_len = plain.size();
        *out_data = static_cast<uint8_t*>(std::malloc(plain.size() > 0 ? plain.size() : 1));
        if (!plain.empty()) std::memcpy(*out_data, plain.data(), plain.size());

        // Promote back to RAM if it fits within RAM budget
        if (plain.size() + k.size() <= eng->max_ram_bytes) {
            eng->lru_list.push_front(RamNode{k, std::move(plain)});
            eng->ram_map[k] = eng->lru_list.begin();
            eng->current_ram_bytes += (eng->lru_list.front().data.size() + k.size());
            eng->disk_map.erase(dit);
            enforce_ram_limit(eng);
        }
        return 0;
    }

    return 1; // Key not found
}

void inte_free_buf(uint8_t* buf) {
    if (buf) std::free(buf);
}

int inte_delete(InteHandle handle, const char* key) {
    if (!handle || !key) return -1;
    auto* eng = static_cast<InteEngine*>(handle);
    std::lock_guard<std::mutex> lock(eng->mtx);

    std::string k(key);
    bool found = false;

    auto rit = eng->ram_map.find(k);
    if (rit != eng->ram_map.end()) {
        eng->current_ram_bytes -= (rit->second->data.size() + rit->second->key.size());
        eng->lru_list.erase(rit->second);
        eng->ram_map.erase(rit);
        found = true;
    }
    if (eng->disk_map.erase(k) > 0) {
        found = true;
    }
    return found ? 0 : 1;
}

void inte_stats(InteHandle handle, size_t* out_ram_used, size_t* out_ram_items, size_t* out_disk_items) {
    if (!handle) return;
    auto* eng = static_cast<InteEngine*>(handle);
    std::lock_guard<std::mutex> lock(eng->mtx);

    if (out_ram_used) *out_ram_used = eng->current_ram_bytes;
    if (out_ram_items) *out_ram_items = eng->ram_map.size();
    if (out_disk_items) *out_disk_items = eng->disk_map.size();
}

void inte_disk_stats(InteHandle handle, size_t* out_active_bytes, size_t* out_file_bytes) {
    if (!handle) return;
    auto* eng = static_cast<InteEngine*>(handle);
    std::lock_guard<std::mutex> lock(eng->mtx);

    size_t active = 0;
    for (const auto& [k, entry] : eng->disk_map) {
        active += entry.cipher_len;
    }

    size_t file_sz = 0;
    std::error_code ec;
    if (fs::exists(eng->data_path, ec)) {
        file_sz = static_cast<size_t>(fs::file_size(eng->data_path, ec));
    }

    if (out_active_bytes) *out_active_bytes = active;
    if (out_file_bytes) *out_file_bytes = file_sz;
}

int inte_compact(InteHandle handle) {
    if (!handle) return -1;
    auto* eng = static_cast<InteEngine*>(handle);
    std::lock_guard<std::mutex> lock(eng->mtx);

    // If nothing is on disk, just truncate data file & save empty index
    if (eng->disk_map.empty()) {
        std::ofstream trunc_out(eng->data_path, std::ios::binary | std::ios::trunc);
        trunc_out.close();
        save_index(eng);
        return 0;
    }

    std::ifstream in(eng->data_path, std::ios::binary);
    if (!in.is_open()) return -2;

    std::string tmp_path = eng->data_path + ".tmp";
    std::ofstream out(tmp_path, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) return -3;

    std::unordered_map<std::string, DiskEntry> new_disk_map;
    new_disk_map.reserve(eng->disk_map.size());

    std::vector<uint8_t> copy_buf;
    uint64_t new_offset = 0;

    for (const auto& [k, old_entry] : eng->disk_map) {
        copy_buf.resize(old_entry.cipher_len);
        in.seekg(old_entry.offset);
        if (!in.read(reinterpret_cast<char*>(copy_buf.data()), old_entry.cipher_len)) {
            out.close();
            fs::remove(tmp_path);
            return -4;
        }

        out.write(reinterpret_cast<const char*>(copy_buf.data()), old_entry.cipher_len);
        if (!out.good()) {
            out.close();
            fs::remove(tmp_path);
            return -5;
        }

        DiskEntry updated = old_entry;
        updated.offset = new_offset;
        new_disk_map[k] = updated;
        new_offset += old_entry.cipher_len;
    }

    in.close();
    out.flush();
    out.close();

    // Atomically swap compacted file over old fragmented file
    std::error_code ec;
    fs::rename(tmp_path, eng->data_path, ec);
    if (ec) {
        fs::remove(tmp_path);
        return -6;
    }

    eng->disk_map = std::move(new_disk_map);
    save_index(eng);

#ifdef __linux__
    copy_buf.clear();
    copy_buf.shrink_to_fit();
    malloc_trim(0);
#endif

    return 0;
}

// Helper: Read single item into 'out_plain' without altering LRU cache or promoting to RAM
static bool read_item_no_promote(InteEngine* eng, const std::string& k, std::vector<uint8_t>& out_plain) {
    std::lock_guard<std::mutex> lock(eng->mtx);

    auto rit = eng->ram_map.find(k);
    if (rit != eng->ram_map.end()) {
        out_plain = rit->second->data;
        return true;
    }

    auto dit = eng->disk_map.find(k);
    if (dit != eng->disk_map.end()) {
        const DiskEntry& entry = dit->second;
        std::ifstream in(eng->data_path, std::ios::binary);
        if (!in.is_open()) return false;

        in.seekg(entry.offset);
        std::vector<uint8_t> cipher(entry.cipher_len);
        in.read(reinterpret_cast<char*>(cipher.data()), entry.cipher_len);

        return aes_gcm_decrypt(eng->key, cipher, entry.iv, entry.tag, out_plain);
    }
    return false;
}

int inte_scan_prefix(InteHandle handle, const char* prefix, const char* contains_filter,
                     InteScanCallback cb, void* user_data) {
    if (!handle || !prefix || !cb) return -1;
    auto* eng = static_cast<InteEngine*>(handle);

    std::string pfx(prefix);
    std::string filter = contains_filter ? std::string(contains_filter) : "";

    // 1. Snapshot matching keys quickly under lock
    std::vector<std::string> matched_keys;
    {
        std::lock_guard<std::mutex> lock(eng->mtx);
        for (const auto& [k, _] : eng->ram_map) {
            if (k.compare(0, pfx.size(), pfx) == 0) matched_keys.push_back(k);
        }
        for (const auto& [k, _] : eng->disk_map) {
            if (k.compare(0, pfx.size(), pfx) == 0) matched_keys.push_back(k);
        }
    }

    std::sort(matched_keys.begin(), matched_keys.end());
    matched_keys.erase(std::unique(matched_keys.begin(), matched_keys.end()), matched_keys.end());

    // 2. Stream one record at a time using a single reused buffer (O(1) memory)
    std::vector<uint8_t> plain_buf;
    int scanned = 0;

    for (const auto& k : matched_keys) {
        if (!read_item_no_promote(eng, k, plain_buf)) continue;

        if (!filter.empty()) {
            auto it = std::search(plain_buf.begin(), plain_buf.end(), filter.begin(), filter.end());
            if (it == plain_buf.end()) continue;
        }

        scanned++;
        int cb_res = cb(k.c_str(), plain_buf.data(), plain_buf.size(), user_data);
        if (cb_res != 0) break; // Early stop requested by caller
    }

#ifdef __linux__
    plain_buf.clear();
    plain_buf.shrink_to_fit();
    malloc_trim(0);
#endif

    return scanned;
}

int inte_aggregate_double_prefix(InteHandle handle, const char* prefix, size_t value_offset,
                                 size_t* out_count, double* out_sum, double* out_min, double* out_max) {
    if (!handle || !prefix) return -1;
    auto* eng = static_cast<InteEngine*>(handle);
    std::string pfx(prefix);

    std::vector<std::string> matched_keys;
    {
        std::lock_guard<std::mutex> lock(eng->mtx);
        for (const auto& [k, _] : eng->ram_map) {
            if (k.compare(0, pfx.size(), pfx) == 0) matched_keys.push_back(k);
        }
        for (const auto& [k, _] : eng->disk_map) {
            if (k.compare(0, pfx.size(), pfx) == 0) matched_keys.push_back(k);
        }
    }

    std::vector<uint8_t> plain_buf;
    size_t count = 0;
    double sum = 0.0;
    double min_val = std::numeric_limits<double>::infinity();
    double max_val = -std::numeric_limits<double>::infinity();

    for (const auto& k : matched_keys) {
        if (!read_item_no_promote(eng, k, plain_buf)) continue;
        if (plain_buf.size() < value_offset + sizeof(double)) continue;

        double val = 0.0;
        std::memcpy(&val, plain_buf.data() + value_offset, sizeof(double));

        count++;
        sum += val;
        if (val < min_val) min_val = val;
        if (val > max_val) max_val = val;
    }

    if (out_count) *out_count = count;
    if (out_sum) *out_sum = sum;
    if (out_min) *out_min = (count > 0) ? min_val : 0.0;
    if (out_max) *out_max = (count > 0) ? max_val : 0.0;

    return 0;
}


void inte_close(InteHandle handle) {
    if (!handle) return;
    auto* eng = static_cast<InteEngine*>(handle);
    {
        std::lock_guard<std::mutex> lock(eng->mtx);
        // Flush all remaining hot RAM items to encrypted disk before exit
        for (const auto& node : eng->lru_list) {
            offload_to_disk(eng, node.key, node.data);
        }
        save_index(eng);
    }
    delete eng;
}

} // extern "C"