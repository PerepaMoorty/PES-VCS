// object.c — Content-addressable object store
//
// Object format on disk:
//   "<type> <size>\0<data>"
//
//   - type is one of: "blob", "tree", "commit"
//   - size is the decimal length of <data>
//   - \0 is a literal null byte separating header from data
//
// Example: storing "Hello\n" (6 bytes) as a blob:
//   Header bytes: b l o b   6 \0
//   Data bytes:   H e l l o \n
//   SHA-256 is computed over the ENTIRE thing (header + data)
//
// Objects are sharded by the first 2 hex characters of their hash:
//   .pes/objects/a1/9c4e6f8a0b...
//
// PROVIDED functions: compute_hash, object_path, object_exists, hash_to_hex, hex_to_hash
// IMPLEMENTED functions: object_write, object_read

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ─── IMPLEMENTED ─────────────────────────────────────────────────────────────

// object_write: builds the full object (header + data), hashes it,
// then writes it to the shard directory. File writing is not yet done.
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    // Step 1: Choose the type string for the header
    const char *type_str;
    switch (type) {
        case OBJ_BLOB:   type_str = "blob";   break;
        case OBJ_TREE:   type_str = "tree";   break;
        case OBJ_COMMIT: type_str = "commit"; break;
        default: return -1;
    }

    // Step 2: Build the header string e.g. "blob 16\0"
    // snprintf writes the null terminator, so header_len includes it
    char header[64];
    int header_len = snprintf(header, sizeof(header), "%s %zu", type_str, len) + 1;

    // Step 3: Allocate full object = header bytes + data bytes
    size_t full_len = (size_t)header_len + len;
    uint8_t *full_obj = malloc(full_len);
    if (!full_obj) return -1;
    memcpy(full_obj, header, header_len);
    memcpy(full_obj + header_len, data, len);

    // Step 4: SHA-256 hash of the full object
    ObjectID id;
    compute_hash(full_obj, full_len, &id);
    if (id_out) *id_out = id;

    free(full_obj);

    // File writing will be added in the next commit
    return 0;
}

int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    (void)id; (void)type_out; (void)data_out; (void)len_out;
    return -1;
}