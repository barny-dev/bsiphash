#ifndef B_SIPHASH_H
#define B_SIPHASH_H

#include <stddef.h>
#include <stdint.h>

extern uint64_t BSIPHASH_C0;
extern uint64_t BSIPHASH_C1;
extern uint64_t BSIPHASH_C2;
extern uint64_t BSIPHASH_C3;

struct BSipHash_Key {
    uint8_t value[16];
};

struct BSipHash_State {
    uint64_t v0;
    uint64_t v1;
    uint64_t v2;
    uint64_t v3;
};

struct BSipHash_State bsiphash_initialize_from_key(struct BSipHash_Key key);
struct BSipHash_State bsiphash_initialize_from_pair(uint64_t k0, uint64_t k1);
struct BSipHash_State bsiphash_compress(struct BSipHash_State state, uint64_t input, size_t c);
struct BSipHash_State bsiphash_sipround(struct BSipHash_State state);
uint64_t bsiphash_remainder(uint8_t* rem, size_t rem_len, size_t data_len);
uint64_t bsiphash_finalize(struct BSipHash_State state, size_t d);

uint64_t bsiphash(struct BSipHash_Key key, uint8_t *data, size_t len, size_t c, size_t d);
uint64_t bsiphash_1_3(struct BSipHash_Key key, uint8_t *data, size_t len);
uint64_t bsiphash_2_4(struct BSipHash_Key key, uint8_t* data, size_t len);


struct BSipHash_Hasher {
    struct BSipHash_State state;
    uint8_t left[7];
    uint8_t left_count;
    uint8_t overall_count;
};


struct BSipHash_Hasher bsiphasher_initialize_from_key(struct BSipHash_Key key);
struct BSipHash_Hasher bsiphasher_initialize_from_pair(uint64_t k0, uint64_t k1);

void bsiphasher_feed(struct BSipHash_Hasher* hasher, uint8_t* data, size_t len, size_t c);
void bsiphasher_feed_1(struct BSipHash_Hasher* hasher, uint8_t *data, size_t len);
void bsiphasher_feed_2(struct BSipHash_Hasher* hasher, uint8_t *data, size_t len);
uint64_t bsiphasher_finalize(struct BSipHash_Hasher* hasher, size_t c, size_t d);
uint64_t bsiphasher_finalize_1_3(struct BSipHash_Hasher* hasher);
uint64_t bsiphasher_finalize_2_4(struct BSipHash_Hasher* hasher);

#endif /* B_SIPHASH_H */