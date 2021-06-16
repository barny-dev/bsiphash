#include "bsiphash.h"
#include <assert.h>

uint64_t BSIPHASH_C0 = 0x736f6d6570736575;
uint64_t BSIPHASH_C1 = 0x646f72616e646f6d;
uint64_t BSIPHASH_C2 = 0x6c7967656e657261;
uint64_t BSIPHASH_C3 = 0x7465646279746573;

static uint64_t bsiphash_u8_array_to_u64_little_endian(uint8_t *data, size_t len) {
    uint8_t arr[8] = { 0 };
    size_t used = len > 8 ? 8 : len;
    for (size_t i = 0; i < used; i++) {
        arr[i] = data[i];
    }
    uint64_t result = (((uint64_t) arr[0]) << 0)
                | (((uint64_t) arr[1]) << 8)
                | (((uint64_t) arr[2]) << 16)
                | (((uint64_t) arr[3]) << 24)
                | (((uint64_t) arr[4]) << 32)
                | (((uint64_t) arr[5]) << 40)
                | (((uint64_t) arr[6]) << 48)
                | (((uint64_t) arr[7]) << 56);
    return result;
}

static uint64_t bsiphash_u64_rotl(uint64_t x, uint64_t n) {
    return (x<<n) | (x>>(-n&63));
}

struct BSipHash_State bsiphash_initialize_from_key(struct BSipHash_Key key) {
    uint64_t k0 = bsiphash_u8_array_to_u64_little_endian(key.value, 8);
    uint64_t k1 = bsiphash_u8_array_to_u64_little_endian(&key.value[8], 8);
    return bsiphash_initialize_from_pair(k0, k1);
}

struct BSipHash_State bsiphash_initialize_from_pair(uint64_t k0, uint64_t k1) {
    struct BSipHash_State state;
    state.v0 = k0 ^ BSIPHASH_C0;
    state.v1 = k1 ^ BSIPHASH_C1;
    state.v2 = k0 ^ BSIPHASH_C2;
    state.v3 = k1 ^ BSIPHASH_C3;
    return state;
}

struct BSipHash_State bsiphash_compress(struct BSipHash_State state, uint64_t input, size_t c) {
    struct BSipHash_State new_state = state;
    new_state.v3 ^= input;
    for (size_t i = 0; i < c; i++) {
        new_state = bsiphash_sipround(new_state);
    }
    new_state.v0 ^= input;
    return new_state;
}

struct BSipHash_State bsiphash_sipround(struct BSipHash_State state) {
    struct BSipHash_State new_state = state;
    new_state.v0 += new_state.v1;
    new_state.v2 += new_state.v3;
    new_state.v1 = bsiphash_u64_rotl(new_state.v1, 13);
    new_state.v3 = bsiphash_u64_rotl(new_state.v3, 16);
    new_state.v1 ^= new_state.v0;
    new_state.v3 ^= new_state.v2;
    new_state.v0 = bsiphash_u64_rotl(new_state.v0, 32);
    new_state.v2 += new_state.v1;
    new_state.v0 += new_state.v3;
    new_state.v1 = bsiphash_u64_rotl(new_state.v1, 17);
    new_state.v3 = bsiphash_u64_rotl(new_state.v3, 21);
    new_state.v1 ^= new_state.v2;
    new_state.v3 ^= new_state.v0;
    new_state.v2 = bsiphash_u64_rotl(new_state.v2, 32);
    return new_state;
}

uint64_t bsiphash_remainder(uint8_t* rem, size_t rem_len, size_t data_len) {
    assert(rem != NULL);
    assert(rem_len < 8);
    return bsiphash_u8_array_to_u64_little_endian(rem, rem_len) | ((uint64_t)(data_len % 256) << 56);
}

uint64_t bsiphash_finalize(struct BSipHash_State state, size_t d) {
    state.v2 ^= UINT64_C(0xff);
    for (size_t i = 0; i < d; i++) {
        state = bsiphash_sipround(state);
    }
    return state.v0 ^ state.v1 ^ state.v2 ^ state.v3;
}

uint64_t bsiphash(struct BSipHash_Key key, uint8_t *data, size_t len, size_t c, size_t d) {
    struct BSipHash_State state = bsiphash_initialize_from_key(key);
    size_t n = len / 8;
    size_t rem_len = len % 8;
    for (size_t i = 0; i < n; i++) {
        uint64_t m = bsiphash_u8_array_to_u64_little_endian(&data[8 * i], 8);
        state = bsiphash_compress(state, m, c);
    }
    uint64_t last = bsiphash_remainder(&data[8*n], rem_len, len);
    state = bsiphash_compress(state, last, c);
    return bsiphash_finalize(state, d);
}

uint64_t bsiphash_1_3(struct BSipHash_Key key, uint8_t* data, size_t len) {
    return bsiphash(key, data, len, 1, 3);
}

uint64_t bsiphash_2_4(struct BSipHash_Key key, uint8_t* data, size_t len) {
    return bsiphash(key, data, len, 2, 4);
}

struct BSipHash_Hasher bsiphasher_initialize_from_key(struct BSipHash_Key key) {
    struct BSipHash_State state = bsiphash_initialize_from_key(key);
    return (struct BSipHash_Hasher) { state, { 0, 0, 0, 0, 0, 0, 0 }, 0, 0};
}

struct BSipHash_Hasher bsiphasher_initialize_from_pair(uint64_t k0, uint64_t k1) {
    struct BSipHash_State state = bsiphash_initialize_from_pair(k0, k1);
    return (struct BSipHash_Hasher) { state, { 0, 0, 0, 0, 0, 0, 0 }, 0, 0};
}

void bsiphasher_feed(struct BSipHash_Hasher *hasher, uint8_t *data, size_t len, size_t c) {
    assert(hasher != NULL);
    assert(hasher->left_count < 8);
    assert(data != NULL);
    
    // case previous data left in hasher + new data < 8 bytes
    if (hasher->left_count + len < 8) {
        for (size_t i = 0; i < len; i++) {
            hasher->left[hasher->left_count + i] = data[i];
        }
        hasher->left_count += len;
        hasher->overall_count += len;
        return;
    }
    
    // first compression includes previous data left in hasher 
    uint8_t left[8];
    for (size_t i = 0; i < hasher->left_count; i++) {
        left[i] = hasher->left[i];
    }
    size_t pre = 8 - hasher->left_count;
    for (size_t i = 0; i < pre; i++) {
        left[hasher->left_count + i] = data[i];
    }
    uint64_t m = bsiphash_u8_array_to_u64_little_endian(left, 8);
    struct BSipHash_State state = bsiphash_compress(hasher->state, m, c);

    size_t iter_len = len - pre;
    size_t n = iter_len / 8; 
    size_t rem_len = iter_len % 8;
    for (size_t i = 0; i < n; i++) {
        m = bsiphash_u8_array_to_u64_little_endian(&data[pre + (8 * i)], i);
        state = bsiphash_compress(hasher->state, m, c);
    }
    hasher->state = state;

    // leave leftover data in hasher
    size_t last_start = len - rem_len;
    for (size_t i = 0; i < rem_len; i++) {
        hasher->left[i] = data[last_start + i]; 
    }
    for (size_t i = 0; i < (7 - rem_len); i++) {
        hasher->left[rem_len + i] = 0;
    }
    hasher->left_count = rem_len;
    hasher->overall_count += len;
}


void bsiphasher_feed_1(struct BSipHash_Hasher *hasher, uint8_t *data, size_t len) {
    bsiphasher_feed(hasher, data, len, 1);
}

void bsiphasher_feed_2(struct BSipHash_Hasher* hasher, uint8_t *data, size_t len) {
    bsiphasher_feed(hasher, data, len, 2);
}


uint64_t bsiphasher_finalize(struct BSipHash_Hasher* hasher, size_t c, size_t d) {
    assert(hasher != NULL);
    assert(hasher->left_count < 8);
    
    uint64_t last = bsiphash_remainder(hasher->left, hasher->left_count, hasher->overall_count);
    struct BSipHash_State state = bsiphash_compress(hasher->state, last, c);
    return bsiphash_finalize(state, d);
}

uint64_t bsiphasher_finalize_1_3(struct BSipHash_Hasher* hasher) {
    return bsiphasher_finalize(hasher, 1, 3);
}

uint64_t bsiphasher_finalize_2_4(struct BSipHash_Hasher* hasher) {
    return bsiphasher_finalize(hasher, 2, 4);
}