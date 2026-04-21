// tree.c — Tree object serialization and construction
//
// A tree object represents one directory level.
// Each entry in the tree is:
//   "<mode-octal> <name>\0<32-byte-binary-hash>"
//
// Entries are sorted by name before serialization so the same set of
// files always produces the identical binary (and therefore the same hash).
//
// tree_from_index strategy:
//   - Load the index (flat list of staged file paths)
//   - Recursively group entries by directory prefix
//   - For each level: files become BLOB entries, subdirs become TREE entries
//   - Serialize each level and write it to the object store
//   - Return the root tree's ObjectID
//
// PROVIDED functions: get_file_mode, tree_parse, tree_serialize
// IMPLEMENTED functions: tree_from_index

#include "tree.h"
#include "index.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

// Forward declaration
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out);

// ─── Mode Constants ─────────────────────────────────────────────────────────

#define MODE_FILE      0100644
#define MODE_EXEC      0100755
#define MODE_DIR       0040000

// ─── PROVIDED ───────────────────────────────────────────────────────────────

uint32_t get_file_mode(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return 0;
    if (S_ISDIR(st.st_mode))  return MODE_DIR;
    if (st.st_mode & S_IXUSR) return MODE_EXEC;
    return MODE_FILE;
}

int tree_parse(const void *data, size_t len, Tree *tree_out) {
    tree_out->count = 0;
    const uint8_t *ptr = (const uint8_t *)data;
    const uint8_t *end = ptr + len;

    while (ptr < end && tree_out->count < MAX_TREE_ENTRIES) {
        TreeEntry *entry = &tree_out->entries[tree_out->count];

        const uint8_t *space = memchr(ptr, ' ', end - ptr);
        if (!space) return -1;

        char mode_str[16] = {0};
        size_t mode_len = space - ptr;
        if (mode_len >= sizeof(mode_str)) return -1;
        memcpy(mode_str, ptr, mode_len);
        entry->mode = strtol(mode_str, NULL, 8);
        ptr = space + 1;

        const uint8_t *null_byte = memchr(ptr, '\0', end - ptr);
        if (!null_byte) return -1;

        size_t name_len = null_byte - ptr;
        if (name_len >= sizeof(entry->name)) return -1;
        memcpy(entry->name, ptr, name_len);
        entry->name[name_len] = '\0';
        ptr = null_byte + 1;

        if (ptr + HASH_SIZE > end) return -1;
        memcpy(entry->hash.hash, ptr, HASH_SIZE);
        ptr += HASH_SIZE;

        tree_out->count++;
    }
    return 0;
}

static int compare_tree_entries(const void *a, const void *b) {
    return strcmp(((const TreeEntry *)a)->name, ((const TreeEntry *)b)->name);
}

int tree_serialize(const Tree *tree, void **data_out, size_t *len_out) {
    size_t max_size = tree->count * 296;
    uint8_t *buffer = malloc(max_size);
    if (!buffer) return -1;

    Tree sorted_tree = *tree;
    qsort(sorted_tree.entries, sorted_tree.count, sizeof(TreeEntry), compare_tree_entries);

    size_t offset = 0;
    for (int i = 0; i < sorted_tree.count; i++) {
        const TreeEntry *entry = &sorted_tree.entries[i];
        int written = sprintf((char *)buffer + offset, "%o %s", entry->mode, entry->name);
        offset += written + 1;
        memcpy(buffer + offset, entry->hash.hash, HASH_SIZE);
        offset += HASH_SIZE;
    }

    *data_out = buffer;
    *len_out = offset;
    return 0;
}

// ─── IMPLEMENTED ─────────────────────────────────────────────────────────────

/*
 * write_tree_recursive — builds one tree level for the given prefix.
 *
 * entries   : the full array of index entries
 * count     : total number of entries
 * prefix    : directory prefix we are currently handling, e.g. "" or "src/"
 * id_out    : receives the ObjectID of the written tree object
 *
 * For each index entry whose path starts with prefix:
 *   - Strip the prefix to get the relative name
 *   - If no '/' in the relative name → direct file → BLOB entry
 *   - If '/' present → subdirectory → recurse, then add TREE entry
 */
static int write_tree_recursive(const IndexEntry *entries, int count,
                                 const char *prefix, ObjectID *id_out) {
    Tree tree;
    tree.count = 0;
    size_t prefix_len = strlen(prefix);
    int i = 0;

    while (i < count) {
        const char *path = entries[i].path;

        // Skip entries not under this prefix
        if (strncmp(path, prefix, prefix_len) != 0) { i++; continue; }

        const char *relative = path + prefix_len;
        const char *slash    = strchr(relative, '/');

        if (!slash) {
            // Direct file — add as BLOB entry
            TreeEntry *e = &tree.entries[tree.count++];
            e->mode = entries[i].mode;
            e->hash = entries[i].hash;
            strncpy(e->name, relative, sizeof(e->name) - 1);
            e->name[sizeof(e->name) - 1] = '\0';
            i++;
        } else {
            // Subdirectory handling will be added in the next commit
            i++;
        }
    }

    // Serialize and write this tree level
    void *data; size_t len;
    if (tree_serialize(&tree, &data, &len) != 0) return -1;
    int rc = object_write(OBJ_TREE, data, len, id_out);
    free(data);
    return rc;
}

int tree_from_index(ObjectID *id_out) {
    Index index;
    if (index_load(&index) != 0) return -1;
    return write_tree_recursive(index.entries, index.count, "", id_out);
}