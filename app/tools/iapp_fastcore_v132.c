
#define _GNU_SOURCE
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#if defined(__linux__) || defined(__ANDROID__)
#include <sched.h>
#endif
#include <openssl/md5.h>
#include <openssl/evp.h>
#if defined(__x86_64__) || defined(__i386__)
#include <wmmintrin.h>
#include <emmintrin.h>
#endif
#if defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)
#include <arm_neon.h>
#if defined(__linux__) || defined(__ANDROID__)
#include <sys/auxv.h>
#include <asm/hwcap.h>
#endif
#endif

static inline int s8c(uint8_t x) { return (int)(int8_t)x; }
static inline int c_divc(int a, int b) { return b ? (a / b) : 0; }

/* Locale-independent integer formatting.  Values used by SLKY and dexkey
 * enumeration are small, but this also handles INT_MIN safely. */
static inline int iapt_i32_ascii(int value, char out[16]) {
    char rev[16];
    uint32_t u;
    int n = 0, p = 0;
    if (value < 0) {
        out[p++] = '-';
        u = (uint32_t)(-(int64_t)value);
    } else {
        u = (uint32_t)value;
    }
    do {
        rev[n++] = (char)('0' + (u % 10u));
        u /= 10u;
    } while (u != 0u);
    while (n) out[p++] = rev[--n];
    return p;
}

static inline void iapt_slky_post_transform(uint8_t digest[16], int remainder,
        const uint8_t *post, int post_len) {
    const int c2 = remainder + 8;
    const int direct_post = (post && post_len >= 16);
    for (int i = 0; i < 16; i++) {
        int cur = s8c(digest[i]);
        int r = (cur < 0 ? -cur : cur) & 15; /* abs(cur) % 16 */
        int v = cur;
        if (r > 8) {
            v = s8c((uint8_t)(v ^ c2));
            digest[i] = (uint8_t)v;
        }
        /* Preserve the original in-place dependency/order exactly. */
        int old_r = s8c(digest[r]);
        digest[r] = (uint8_t)v;
        if (post && post_len > 0) {
            const uint8_t pb = direct_post ? post[i] : post[i % post_len];
            digest[i] = (uint8_t)(old_r ^ pb);
        } else {
            digest[i] = (uint8_t)old_r;
        }
    }
}

int iapp_slky_core(const void *a_ptr, int a_len, const void *b_ptr, int b_len,
        const void *post_ptr, int post_len, void *out_ptr) {
    if (!a_ptr || a_len <= 0 || !out_ptr) return -1;
    const uint8_t *a = (const uint8_t *)a_ptr;
    const uint8_t *b = (const uint8_t *)b_ptr;
    const uint8_t *post = (const uint8_t *)post_ptr;
    const int has_b = (b && b_len > 0);

    int signed_sum = a_len;
    for (int i = 0; i < a_len; i++) signed_sum += s8c(a[i]);
    const int avg = signed_sum / a_len; /* C99: truncates toward zero */
    const int first = s8c(a[0]);
    const int last = s8c(a[a_len - 1]);
    const int mix = (signed_sum + last * first) / a_len;
    const int remainder = signed_sum % a_len;

    char mixbuf[16];
    const int mixlen = iapt_i32_ascii(mix, mixbuf);
    const int total = a_len + mixlen + (has_b ? b_len : 0);
    uint8_t stackbuf[512];
    uint8_t *buf = stackbuf;
    if (total > (int)sizeof(stackbuf)) {
        buf = (uint8_t *)malloc((size_t)total);
        if (!buf) return -3;
    }

    /* Fuse concatenation and XOR into one write pass. */
    const uint8_t mask = (uint8_t)avg;
    int pos = 0;
    for (int i = 0; i < a_len; i++) buf[pos++] = (uint8_t)(a[i] ^ mask);
    for (int i = 0; i < mixlen; i++) buf[pos++] = (uint8_t)(((uint8_t)mixbuf[i]) ^ mask);
    if (has_b) for (int i = 0; i < b_len; i++) buf[pos++] = (uint8_t)(b[i] ^ mask);

    uint8_t digest[16];
    MD5(buf, (size_t)total, digest);
    if (buf != stackbuf) free(buf);
    iapt_slky_post_transform(digest, remainder + (has_b ? b_len : 0), post, post_len);
    memcpy(out_ptr, digest, 16);
    return 0;
}

/* p24/p25 are overwhelmingly SLKY(16 bytes, 16 bytes).  This exact-specialized
 * path avoids generic allocation/branching while retaining the same MD5 input
 * and the same in-place post transform. */
static inline int iapp_slky_16_16(const uint8_t a[16], const uint8_t b[16],
        const uint8_t *post, int post_len, uint8_t out[16]) {
    int signed_sum = 16;
    for (int i = 0; i < 16; i++) signed_sum += s8c(a[i]);
    const int avg = signed_sum / 16;
    const int mix = (signed_sum + s8c(a[0]) * s8c(a[15])) / 16;
    const int remainder = signed_sum % 16;
    char mixbuf[16];
    const int mixlen = iapt_i32_ascii(mix, mixbuf);
    uint8_t buf[48];
    const uint8_t mask = (uint8_t)avg;
    int pos = 0;
    for (int i = 0; i < 16; i++) buf[pos++] = (uint8_t)(a[i] ^ mask);
    for (int i = 0; i < mixlen; i++) buf[pos++] = (uint8_t)(((uint8_t)mixbuf[i]) ^ mask);
    for (int i = 0; i < 16; i++) buf[pos++] = (uint8_t)(b[i] ^ mask);
    uint8_t digest[16];
    MD5(buf, (size_t)pos, digest);
    iapt_slky_post_transform(digest, remainder + 16, post, post_len);
    memcpy(out, digest, 16);
    return 0;
}

#if defined(__x86_64__) || defined(__i386__)
#define IAPT_AES_EXPAND_STEP(k,rc) do { \
    __m128i _t=_mm_aeskeygenassist_si128((k),(rc)); _t=_mm_shuffle_epi32(_t,0xff); \
    __m128i _x=(k); _x=_mm_xor_si128(_x,_mm_slli_si128(_x,4)); \
    _x=_mm_xor_si128(_x,_mm_slli_si128(_x,4)); _x=_mm_xor_si128(_x,_mm_slli_si128(_x,4)); \
    (k)=_mm_xor_si128(_x,_t); \
} while(0)
__attribute__((target("aes,sse2"))) static inline void iapt_aes128_expand_x86(const uint8_t key[16],__m128i rk[11]){
    rk[0]=_mm_loadu_si128((const __m128i*)key);rk[1]=rk[0];IAPT_AES_EXPAND_STEP(rk[1],0x01);rk[2]=rk[1];IAPT_AES_EXPAND_STEP(rk[2],0x02);rk[3]=rk[2];IAPT_AES_EXPAND_STEP(rk[3],0x04);rk[4]=rk[3];IAPT_AES_EXPAND_STEP(rk[4],0x08);rk[5]=rk[4];IAPT_AES_EXPAND_STEP(rk[5],0x10);rk[6]=rk[5];IAPT_AES_EXPAND_STEP(rk[6],0x20);rk[7]=rk[6];IAPT_AES_EXPAND_STEP(rk[7],0x40);rk[8]=rk[7];IAPT_AES_EXPAND_STEP(rk[8],0x80);rk[9]=rk[8];IAPT_AES_EXPAND_STEP(rk[9],0x1b);rk[10]=rk[9];IAPT_AES_EXPAND_STEP(rk[10],0x36);
}
__attribute__((target("aes,sse2"))) static inline void iapt_aes128_decrypt_x86(const uint8_t in[16],const uint8_t key[16],uint8_t out[16]){
    __m128i rk[11];iapt_aes128_expand_x86(key,rk);__m128i x=_mm_loadu_si128((const __m128i*)in);x=_mm_xor_si128(x,rk[10]);for(int i=9;i>=1;i--)x=_mm_aesdec_si128(x,_mm_aesimc_si128(rk[i]));x=_mm_aesdeclast_si128(x,rk[0]);_mm_storeu_si128((__m128i*)out,x);
}
#endif

#if defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)
static const uint8_t iapt_aes_sbox[256] = {
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16};
static inline uint32_t iapt_aes_rotword(uint32_t w){return (w<<8)|(w>>24);}
static inline uint32_t iapt_aes_subword(uint32_t w){
    return ((uint32_t)iapt_aes_sbox[(w>>24)&255]<<24)|((uint32_t)iapt_aes_sbox[(w>>16)&255]<<16)|
           ((uint32_t)iapt_aes_sbox[(w>>8)&255]<<8)|(uint32_t)iapt_aes_sbox[w&255];
}
static inline void iapt_aes128_expand_arm(const uint8_t key[16],uint8x16_t rk[11]){
    uint32_t w[44];
    for(int i=0;i<4;i++)w[i]=((uint32_t)key[4*i]<<24)|((uint32_t)key[4*i+1]<<16)|((uint32_t)key[4*i+2]<<8)|key[4*i+3];
    static const uint8_t rc[10]={1,2,4,8,16,32,64,128,27,54};
    for(int i=4;i<44;i++){uint32_t t=w[i-1];if((i&3)==0)t=iapt_aes_subword(iapt_aes_rotword(t))^((uint32_t)rc[i/4-1]<<24);w[i]=w[i-4]^t;}
    uint8_t b[16];
    for(int r=0;r<11;r++){for(int j=0;j<4;j++){uint32_t v=w[4*r+j];b[4*j]=(uint8_t)(v>>24);b[4*j+1]=(uint8_t)(v>>16);b[4*j+2]=(uint8_t)(v>>8);b[4*j+3]=(uint8_t)v;}rk[r]=vld1q_u8(b);}
}
static inline void iapt_aes128_decrypt_arm(const uint8_t in[16],const uint8_t key[16],uint8_t out[16]){
    uint8x16_t rk[11];iapt_aes128_expand_arm(key,rk);uint8x16_t x=vld1q_u8(in);x=veorq_u8(x,rk[10]);
    for(int i=9;i>=1;i--){x=vaesdq_u8(x,rk[i]);x=vaesimcq_u8(x);}
    x=vaesdq_u8(x,rk[0]);vst1q_u8(out,x);
}
static inline int iapt_arm_aes_runtime(void){
#if defined(HWCAP_AES) && (defined(__linux__) || defined(__ANDROID__))
    return (getauxval(AT_HWCAP)&HWCAP_AES)!=0;
#else
    return 1;
#endif
}
#endif

static int iapt_fast_aes_state=-1;
static int iapt_fast_aes128_available(void){
    if(iapt_fast_aes_state>=0)return iapt_fast_aes_state;
#if defined(__x86_64__) || defined(__i386__)
    #if defined(__GNUC__) || defined(__clang__)
    __builtin_cpu_init();
    if(__builtin_cpu_supports("aes")){
        static const uint8_t k[16]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
        static const uint8_t c[16]={0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};
        static const uint8_t p[16]={0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
        uint8_t o[16];iapt_aes128_decrypt_x86(c,k,o);iapt_fast_aes_state=memcmp(o,p,16)==0;return iapt_fast_aes_state;
    }
    #endif
#endif
#if defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)
    if(iapt_arm_aes_runtime()){
        static const uint8_t k[16]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
        static const uint8_t c[16]={0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};
        static const uint8_t p[16]={0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
        uint8_t o[16];iapt_aes128_decrypt_arm(c,k,o);iapt_fast_aes_state=memcmp(o,p,16)==0;return iapt_fast_aes_state;
    }
#endif
    iapt_fast_aes_state=0;return 0;
}
static inline int iapt_fast_aes128_decrypt(const uint8_t in[16],const uint8_t key[16],uint8_t out[16]){
#if defined(__x86_64__) || defined(__i386__)
    if(iapt_fast_aes128_available()){iapt_aes128_decrypt_x86(in,key,out);return 1;}
#elif defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)
    if(iapt_fast_aes128_available()){iapt_aes128_decrypt_arm(in,key,out);return 1;}
#endif
    return 0;
}

static const EVP_CIPHER *pick_ecb(int key_len) {
    if (key_len == 16) return EVP_aes_128_ecb();
    if (key_len == 24) return EVP_aes_192_ecb();
    if (key_len == 32) return EVP_aes_256_ecb();
    return NULL;
}
static const EVP_CIPHER *pick_cbc(int key_len) {
    if (key_len == 16) return EVP_aes_128_cbc();
    if (key_len == 24) return EVP_aes_192_cbc();
    if (key_len == 32) return EVP_aes_256_cbc();
    return NULL;
}

/* Fast enumeration gates.  The strict tail-marker pass is attempted first:
 * after PKCS#7 succeeds, decrypt only the final data block and compare it with
 * the candidate-specific end marker of <package>.project.  If an APK uses a
 * different layout, Python reruns with the prefix gate and then full validation,
 * preserving correctness. */
static size_t iapt_mian_prefix_limit = 0;
static int iapt_tail_gate_enabled = 0;
static uint8_t iapt_tail_name[512];
static int iapt_tail_name_len = 0;
/* -1 tests both idbfj variants, 0=no-signature only, 1=signature only. */
static int iapt_idbfj_variant_mode = -1;
int iapp_set_mian_prefix_limit(size_t n) { iapt_mian_prefix_limit = n; return 0; }
int iapp_set_idbfj_variant_mode(int mode) {
    iapt_idbfj_variant_mode = (mode == 0 || mode == 1) ? mode : -1;
    return 0;
}
int iapp_set_tail_marker_gate(const void *name_ptr, int name_len, int enabled) {
    iapt_tail_gate_enabled = enabled ? 1 : 0;
    iapt_tail_name_len = 0;
    if (!enabled) return 0;
    if (!name_ptr || name_len <= 0 || name_len > (int)sizeof(iapt_tail_name)) return -1;
    memcpy(iapt_tail_name, name_ptr, (size_t)name_len);
    iapt_tail_name_len = name_len;
    return 0;
}

int iapp_aes_cbc_padding_valid(const void *ct_ptr, size_t ct_len, const void *key_ptr, int key_len) {
    if (!ct_ptr || !key_ptr || ct_len == 0 || (ct_len & 15)) return 0;
    const EVP_CIPHER *cipher = pick_ecb(key_len);
    if (!cipher) return 0;
    const uint8_t *ct = (const uint8_t *)ct_ptr;
    const uint8_t *key = (const uint8_t *)key_ptr;
    uint8_t block[32];
    if(key_len==16 && iapt_fast_aes128_decrypt(ct+ct_len-16,key,block)){
        const uint8_t *prev=(ct_len==16)?key:(ct+ct_len-32);for(int i=0;i<16;i++)block[i]^=prev[i];uint8_t pad=block[15];if(pad<1||pad>16)return 0;for(int i=0;i<pad;i++)if(block[15-i]!=pad)return 0;return 1;
    }
    int outl = 0, finl = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;
    int ok = 0;
    if (EVP_DecryptInit_ex(ctx, cipher, NULL, key, NULL) == 1) {
        EVP_CIPHER_CTX_set_padding(ctx, 0);
        if (EVP_DecryptUpdate(ctx, block, &outl, ct + ct_len - 16, 16) == 1 && EVP_DecryptFinal_ex(ctx, block + outl, &finl) == 1) {
            const uint8_t *prev = (ct_len == 16) ? key : (ct + ct_len - 32);
            for (int i = 0; i < 16; i++) block[i] ^= prev[i];
            uint8_t pad = block[15];
            if (pad >= 1 && pad <= 16) {
                ok = 1;
                for (int i = 0; i < pad; i++) if (block[15 - i] != pad) { ok = 0; break; }
            }
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/* Decrypt the last non-padding CBC block and apply the outer XOR transform.
 * For PKCS#7 ciphertext this is ciphertext block n-2; block n-1 is padding. */
static int iapp_aes_cbc_xor_last_data_block(const void *ct_ptr, size_t ct_len,
        const void *key_ptr, int key_len, uint8_t out[16]) {
    if (!ct_ptr || !key_ptr || !out || ct_len < 32 || (ct_len & 15)) return -1;
    const EVP_CIPHER *cipher = pick_ecb(key_len);
    if (!cipher) return -2;
    const uint8_t *ct = (const uint8_t *)ct_ptr;
    const uint8_t *key = (const uint8_t *)key_ptr;
    const uint8_t *cur = ct + ct_len - 32;
    const uint8_t *prev = (ct_len == 32) ? key : (ct + ct_len - 48);
    if(key_len==16 && iapt_fast_aes128_decrypt(cur,key,out)){for(int i=0;i<16;i++)out[i]=(uint8_t)(out[i]^prev[i]^key[i]);return 0;}
    int outl = 0, finl = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -3;
    int ret = -4;
    if (EVP_DecryptInit_ex(ctx, cipher, NULL, key, NULL) == 1) {
        EVP_CIPHER_CTX_set_padding(ctx, 0);
        if (EVP_DecryptUpdate(ctx, out, &outl, cur, 16) == 1 &&
                EVP_DecryptFinal_ex(ctx, out + outl, &finl) == 1) {
            for (int i = 0; i < 16; i++) out[i] = (uint8_t)(out[i] ^ prev[i] ^ key[i % key_len]);
            ret = 0;
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int iapp_aes_cbc_xor_decrypt(const void *ct_ptr, size_t ct_len, const void *key_ptr, int key_len, void *out_ptr, size_t *out_len_ptr) {
    if (!ct_ptr || !key_ptr || !out_ptr || !out_len_ptr || ct_len == 0 || (ct_len & 15)) return -1;
    const EVP_CIPHER *cipher = pick_cbc(key_len);
    if (!cipher) return -2;
    const uint8_t *ct = (const uint8_t *)ct_ptr;
    const uint8_t *key = (const uint8_t *)key_ptr;
    uint8_t *out = (uint8_t *)out_ptr;
    int outl = 0, finl = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -3;
    int ret = -4;
    if (EVP_DecryptInit_ex(ctx, cipher, NULL, key, key) == 1) {
        EVP_CIPHER_CTX_set_padding(ctx, 1);
        if (EVP_DecryptUpdate(ctx, out, &outl, ct, (int)ct_len) == 1 && EVP_DecryptFinal_ex(ctx, out + outl, &finl) == 1) {
            size_t n = (size_t)(outl + finl);
            for (size_t i = 0; i < n; i++) out[i] ^= key[i % (size_t)key_len];
            *out_len_ptr = n;
            ret = 0;
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

static int iapp_aes_cbc_xor_decrypt_prefix(const void *ct_ptr, size_t ct_len,
        const void *key_ptr, int key_len, size_t prefix_limit, void *out_ptr, size_t *out_len_ptr) {
    if (!ct_ptr || !key_ptr || !out_ptr || !out_len_ptr || ct_len < 16 || (ct_len & 15)) return -1;
    const EVP_CIPHER *cipher = pick_cbc(key_len);
    if (!cipher) return -2;
    size_t n = prefix_limit < ct_len ? prefix_limit : ct_len;
    n &= ~(size_t)15;
    if (n < 16) return -3;
    const uint8_t *ct = (const uint8_t *)ct_ptr;
    const uint8_t *key = (const uint8_t *)key_ptr;
    uint8_t *out = (uint8_t *)out_ptr;
    int outl = 0, finl = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -4;
    int ret = -5;
    if (EVP_DecryptInit_ex(ctx, cipher, NULL, key, key) == 1) {
        EVP_CIPHER_CTX_set_padding(ctx, 0);
        if (EVP_DecryptUpdate(ctx, out, &outl, ct, (int)n) == 1 &&
                EVP_DecryptFinal_ex(ctx, out + outl, &finl) == 1) {
            size_t got = (size_t)(outl + finl);
            if (got > n) got = n;
            for (size_t i = 0; i < got; i++) out[i] ^= key[i % (size_t)key_len];
            *out_len_ptr = got;
            ret = 0;
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int iapp_mian_gate_maybe(const void *data_ptr, size_t data_len) {
    if (!data_ptr || data_len == 0) return 0;
    const uint8_t *d = (const uint8_t *)data_ptr;
    const char *needles[] = {"<View", "</View", "<eventItme", "<UIEventset", "LinearLayout", "width=", "height=", "orientation=", "function", "uigo", "call", "fn "};
    size_t n_needles = sizeof(needles) / sizeof(needles[0]);
    size_t n = data_len < 4096 ? data_len : 4096;
    for (size_t k = 0; k < n_needles; k++) {
        const char *s = needles[k];
        size_t m = strlen(s);
        if (m == 0 || m > n) continue;
        for (size_t i = 0; i + m <= n; i++) {
            if (memcmp(d + i, s, m) == 0) return 1;
        }
    }
    return 0;
}


static void xor_repeat16(const uint8_t *seed, const uint8_t *xk, int xk_len, uint8_t out[16]) {
    for (int i = 0; i < 16; i++) out[i] = (uint8_t)(seed[i] ^ xk[i % xk_len]);
}

static int make_fixed_outer_key(const uint8_t *hidden, int hidden_len,
        const char *pkg, int pkg_len, const char *vn, int vn_len,
        const char *vc, int vc_len, const char *label, int label_len,
        const char *fb, int fb_len,
        const uint8_t *post, int post_len, const uint8_t *xk, int xk_len,
        uint8_t outer_key[16]) {
    if (!hidden || hidden_len <= 0 || !post || post_len <= 0 || !xk || xk_len <= 0) return -1;
    int base_len = hidden_len + vn_len + pkg_len + label_len + vc_len + fb_len;
    uint8_t stackbase[512];
    uint8_t *heapbase = NULL;
    uint8_t *base = stackbase;
    if (base_len > (int)sizeof(stackbase)) {
        heapbase = (uint8_t *)malloc((size_t)base_len);
        if (!heapbase) return -2;
        base = heapbase;
    }
    int off = 0;
    memcpy(base + off, hidden, (size_t)hidden_len); off += hidden_len;
    if (vn_len > 0) { memcpy(base + off, vn, (size_t)vn_len); off += vn_len; }
    if (pkg_len > 0) { memcpy(base + off, pkg, (size_t)pkg_len); off += pkg_len; }
    if (label_len > 0) { memcpy(base + off, label, (size_t)label_len); off += label_len; }
    if (vc_len > 0) { memcpy(base + off, vc, (size_t)vc_len); off += vc_len; }
    if (fb_len > 0) { memcpy(base + off, fb, (size_t)fb_len); off += fb_len; }
    uint8_t p19[16], p24[16], p25[16];
    int ok = 0;
    if (iapp_slky_core(base, base_len, hidden, hidden_len, post, post_len, p19) != 0) ok = -3;
    else if (iapp_slky_16_16(p19, p19, post, post_len, p24) != 0) ok = -4;
    else if (iapp_slky_16_16(p19, p24, post, post_len, p25) != 0) ok = -5;
    else xor_repeat16(p25, xk, xk_len, outer_key);
    if (heapbase) free(heapbase);
    return ok;
}

int iapp_fixed_dexkey_scan(const void *ct_ptr, size_t ct_len,
        const void *hidden_ptr, int hidden_len,
        const char *pkg, int pkg_len, const char *vn, int vn_len,
        const char *vc, int vc_len, const char *label, int label_len,
        int start_fb, int stop_fb, int direction,
        const void *post_ptr, int post_len, const void *xk_ptr, int xk_len,
        int *found_fb) {
    if (!ct_ptr || !hidden_ptr || !post_ptr || !xk_ptr || !found_fb) return -1;
    if (direction == 0) direction = (start_fb <= stop_fb) ? 1 : -1;
    int fb = start_fb;
    char fb_buf[32];
    while ((direction > 0 && fb <= stop_fb) || (direction < 0 && fb >= stop_fb)) {
        int fb_len = iapt_i32_ascii(fb, fb_buf);
        if (fb_len > 0 && fb_len < (int)sizeof(fb_buf)) {
            uint8_t outer[16];
            if (make_fixed_outer_key((const uint8_t*)hidden_ptr, hidden_len, pkg, pkg_len, vn, vn_len, vc, vc_len, label, label_len, fb_buf, fb_len, (const uint8_t*)post_ptr, post_len, (const uint8_t*)xk_ptr, xk_len, outer) == 0) {
                if (iapp_aes_cbc_padding_valid(ct_ptr, ct_len, outer, 16)) { *found_fb = fb; return 1; }
            }
        }
        fb += direction;
    }
    return 0;
}

int iapp_fixed_hidden_list_scan(const void *ct_ptr, size_t ct_len,
        const void *hidden_blob, int hidden_count, int hidden_len,
        const char *pkg, int pkg_len, const char *vn, int vn_len,
        const char *vc, int vc_len, const char *label, int label_len,
        const char *fb, int fb_len,
        const void *post_ptr, int post_len, const void *xk_ptr, int xk_len,
        int start_index, int stop_index, int direction, int *found_index) {
    if (!ct_ptr || !hidden_blob || hidden_count <= 0 || hidden_len <= 0 || !post_ptr || !xk_ptr || !found_index) return -1;
    if (start_index < 0) start_index = 0;
    if (stop_index >= hidden_count) stop_index = hidden_count - 1;
    if (direction == 0) direction = (start_index <= stop_index) ? 1 : -1;
    int idx = start_index;
    const uint8_t *blob = (const uint8_t*)hidden_blob;
    while ((direction > 0 && idx <= stop_index) || (direction < 0 && idx >= stop_index)) {
        const uint8_t *hidden = blob + ((size_t)idx * (size_t)hidden_len);
        uint8_t outer[16];
        if (make_fixed_outer_key(hidden, hidden_len, pkg, pkg_len, vn, vn_len, vc, vc_len, label, label_len, fb, fb_len, (const uint8_t*)post_ptr, post_len, (const uint8_t*)xk_ptr, xk_len, outer) == 0) {
            if (iapp_aes_cbc_padding_valid(ct_ptr, ct_len, outer, 16)) { *found_index = idx; return 1; }
        }
        idx += direction;
    }
    return 0;
}


static int mem_find16(const uint8_t *hay, size_t hay_len, const uint8_t needle[16], size_t start) {
    if (!hay || hay_len < 16 || start > hay_len - 16) return -1;
    const uint8_t first = needle[0];
    size_t limit = hay_len - 16;
    for (size_t i = start; i <= limit; i++) {
        if (hay[i] == first && memcmp(hay + i, needle, 16) == 0) return (int)i;
    }
    return -1;
}

static int make_member_markers_c(const char *main_name, int main_len, const uint8_t *hidden, int hidden_len,
        const char *fb, int fb_len, const uint8_t *post, int post_len, uint8_t start[16], uint8_t end[16]) {
    if (!main_name || main_len <= 0 || !hidden || hidden_len <= 0 || !fb || fb_len <= 0) return -1;
    uint8_t b1[256], b2[256];
    int b1_len = hidden_len + fb_len;
    int b2_len = fb_len + hidden_len;
    if (b1_len > (int)sizeof(b1) || b2_len > (int)sizeof(b2)) return -2;
    memcpy(b1, hidden, (size_t)hidden_len); memcpy(b1 + hidden_len, fb, (size_t)fb_len);
    memcpy(b2, fb, (size_t)fb_len); memcpy(b2 + fb_len, hidden, (size_t)hidden_len);
    if (iapp_slky_core((const uint8_t*)main_name, main_len, b1, b1_len, post, post_len, start) != 0) return -3;
    if (iapp_slky_core((const uint8_t*)main_name, main_len, b2, b2_len, post, post_len, end) != 0) return -4;
    return 0;
}

static int make_member_end_marker_c(const uint8_t *name, int name_len,
        const uint8_t *hidden, int hidden_len, const char *fb, int fb_len,
        const uint8_t *post, int post_len, uint8_t end[16]) {
    if (!name || name_len <= 0 || !hidden || hidden_len <= 0 || !fb || fb_len <= 0) return -1;
    uint8_t b2[256];
    int b2_len = fb_len + hidden_len;
    if (b2_len > (int)sizeof(b2)) return -2;
    memcpy(b2, fb, (size_t)fb_len);
    memcpy(b2 + fb_len, hidden, (size_t)hidden_len);
    return iapp_slky_core(name, name_len, b2, b2_len, post, post_len, end);
}

static int make_member_key_c(const char *main_name, int main_len, const uint8_t *hidden, int hidden_len,
        const char *fb, int fb_len, const uint8_t *post, int post_len, const uint8_t *xk, int xk_len, int direct, uint8_t key[16]) {
    if (!main_name || main_len <= 0 || !hidden || hidden_len <= 0 || !fb || fb_len <= 0) return -1;
    uint8_t a[512], seed[16];
    int a_len = main_len + hidden_len + fb_len;
    if (a_len > (int)sizeof(a)) return -2;
    memcpy(a, main_name, (size_t)main_len);
    memcpy(a + main_len, hidden, (size_t)hidden_len);
    memcpy(a + main_len + hidden_len, fb, (size_t)fb_len);
    if (iapp_slky_core(a, a_len, (const uint8_t*)main_name, main_len, post, post_len, seed) != 0) return -3;
    if (direct || !xk || xk_len <= 0) memcpy(key, seed, 16);
    else xor_repeat16(seed, xk, xk_len, key);
    return 0;
}

static int probe_mian_plain_c(const uint8_t *plain, size_t plain_len, const uint8_t *hidden, int hidden_len,
        const char *fb, int fb_len, const uint8_t *post, int post_len, const uint8_t *xk, int xk_len,
        const char *main_name, int main_len, size_t max_main) {
    uint8_t start[16], end[16];
    if (make_member_markers_c(main_name, main_len, hidden, hidden_len, fb, fb_len, post, post_len, start, end) != 0) return 0;
    int s = mem_find16(plain, plain_len, start, 0);
    if (s < 0) return 0;
    size_t data_start = (size_t)s + 16;
    int e = mem_find16(plain, plain_len, end, data_start);
    if (e < 0 || (size_t)e <= data_start) return 0;
    size_t clen = (size_t)e - data_start;
    if (clen == 0 || (clen & 15) || clen > max_main) return 0;
    const uint8_t *ct = plain + data_start;
    uint8_t key[16];
    uint8_t *out = (uint8_t*)malloc(clen + 32);
    if (!out) return 0;
    size_t out_len = 0;
    int ok = 0;
    if (make_member_key_c(main_name, main_len, hidden, hidden_len, fb, fb_len, post, post_len, xk, xk_len, 0, key) == 0) {
        if (iapp_aes_cbc_xor_decrypt(ct, clen, key, 16, out, &out_len) == 0 && iapp_mian_gate_maybe(out, out_len)) ok = 1;
    }
    if (!ok && make_member_key_c(main_name, main_len, hidden, hidden_len, fb, fb_len, post, post_len, xk, xk_len, 1, key) == 0) {
        if (iapp_aes_cbc_xor_decrypt(ct, clen, key, 16, out, &out_len) == 0 && iapp_mian_gate_maybe(out, out_len)) ok = 1;
    }
    free(out);
    return ok;
}

static int probe_outer_to_mian_c(const void *ct_ptr, size_t ct_len, const uint8_t outer[16],
        const uint8_t *hidden, int hidden_len, const char *fb, int fb_len,
        const uint8_t *post, int post_len, const uint8_t *xk, int xk_len,
        const char *main_name, int main_len, size_t max_main) {
    if (!iapp_aes_cbc_padding_valid(ct_ptr, ct_len, outer, 16)) return 0;

    /* Standard iApp containers commonly end with <package>.project's end
     * marker.  This candidate-specific 128-bit check turns a random padding hit
     * into an essentially exact hit using only one additional AES block. */
    if (iapt_tail_gate_enabled && iapt_tail_name_len > 0) {
        uint8_t got[16], expected[16];
        if (iapp_aes_cbc_xor_last_data_block(ct_ptr, ct_len, outer, 16, got) != 0) return 0;
        if (make_member_end_marker_c(iapt_tail_name, iapt_tail_name_len, hidden, hidden_len,
                fb, fb_len, post, post_len, expected) == 0 && memcmp(got, expected, 16) == 0) return 1;
        if (make_member_end_marker_c(iapt_tail_name, iapt_tail_name_len, hidden, hidden_len,
                fb, fb_len, NULL, 0, expected) == 0 && memcmp(got, expected, 16) == 0) return 1;
        return 0;
    }

    /* Fast first pass: main entries are normally near the beginning of the
     * container.  Decrypt a bounded prefix only.  A no-hit result is not final:
     * the Python coordinator reruns the whole range with prefix_limit=0. */
    if (iapt_mian_prefix_limit > 0 && iapt_mian_prefix_limit < ct_len) {
        size_t cap = iapt_mian_prefix_limit & ~(size_t)15;
        if (cap < 16) return 0;
        uint8_t *prefix = (uint8_t*)malloc(cap + 32);
        if (!prefix) return 0;
        size_t prefix_len = 0;
        int ok = 0;
        if (iapp_aes_cbc_xor_decrypt_prefix(ct_ptr, ct_len, outer, 16, cap, prefix, &prefix_len) == 0) {
            if (probe_mian_plain_c(prefix, prefix_len, hidden, hidden_len, fb, fb_len, post, post_len, xk, xk_len, main_name, main_len, max_main)) ok = 1;
            if (!ok && probe_mian_plain_c(prefix, prefix_len, hidden, hidden_len, fb, fb_len, NULL, 0, xk, xk_len, main_name, main_len, max_main)) ok = 1;
        }
        free(prefix);
        return ok;
    }

    uint8_t *plain = (uint8_t*)malloc(ct_len + 32);
    if (!plain) return 0;
    size_t plain_len = 0;
    int ok = 0;
    if (iapp_aes_cbc_xor_decrypt(ct_ptr, ct_len, outer, 16, plain, &plain_len) == 0) {
        if (probe_mian_plain_c(plain, plain_len, hidden, hidden_len, fb, fb_len, post, post_len, xk, xk_len, main_name, main_len, max_main)) ok = 1;
        if (!ok && probe_mian_plain_c(plain, plain_len, hidden, hidden_len, fb, fb_len, NULL, 0, xk, xk_len, main_name, main_len, max_main)) ok = 1;
    }
    free(plain);
    return ok;
}

int iapp_fixed_dexkey_scan_mian(const void *ct_ptr, size_t ct_len,
        const void *hidden_ptr, int hidden_len,
        const char *pkg, int pkg_len, const char *vn, int vn_len,
        const char *vc, int vc_len, const char *label, int label_len,
        int start_fb, int stop_fb, int direction,
        const void *post_ptr, int post_len, const void *xk_ptr, int xk_len,
        const char *main_name, int main_len, size_t max_main, int *found_fb) {
    if (!ct_ptr || !hidden_ptr || !post_ptr || !xk_ptr || !main_name || !found_fb) return -1;
    if (direction == 0) direction = (start_fb <= stop_fb) ? 1 : -1;
    int fb = start_fb;
    char fb_buf[32];
    while ((direction > 0 && fb <= stop_fb) || (direction < 0 && fb >= stop_fb)) {
        int fb_len = iapt_i32_ascii(fb, fb_buf);
        if (fb_len > 0 && fb_len < (int)sizeof(fb_buf)) {
            uint8_t outer[16];
            if (make_fixed_outer_key((const uint8_t*)hidden_ptr, hidden_len, pkg, pkg_len, vn, vn_len, vc, vc_len, label, label_len, fb_buf, fb_len, (const uint8_t*)post_ptr, post_len, (const uint8_t*)xk_ptr, xk_len, outer) == 0) {
                if (probe_outer_to_mian_c(ct_ptr, ct_len, outer, (const uint8_t*)hidden_ptr, hidden_len, fb_buf, fb_len, (const uint8_t*)post_ptr, post_len, (const uint8_t*)xk_ptr, xk_len, main_name, main_len, max_main)) { *found_fb = fb; return 1; }
            }
        }
        fb += direction;
    }
    return 0;
}

int iapp_fixed_hidden_list_scan_mian(const void *ct_ptr, size_t ct_len,
        const void *hidden_blob, int hidden_count, int hidden_len,
        const char *pkg, int pkg_len, const char *vn, int vn_len,
        const char *vc, int vc_len, const char *label, int label_len,
        const char *fb, int fb_len,
        const void *post_ptr, int post_len, const void *xk_ptr, int xk_len,
        int start_index, int stop_index, int direction,
        const char *main_name, int main_len, size_t max_main, int *found_index) {
    if (!ct_ptr || !hidden_blob || hidden_count <= 0 || hidden_len <= 0 || !post_ptr || !xk_ptr || !main_name || !found_index) return -1;
    if (start_index < 0) start_index = 0;
    if (stop_index >= hidden_count) stop_index = hidden_count - 1;
    if (direction == 0) direction = (start_index <= stop_index) ? 1 : -1;
    int idx = start_index;
    const uint8_t *blob = (const uint8_t*)hidden_blob;
    while ((direction > 0 && idx <= stop_index) || (direction < 0 && idx >= stop_index)) {
        const uint8_t *hidden = blob + ((size_t)idx * (size_t)hidden_len);
        uint8_t outer[16];
        if (make_fixed_outer_key(hidden, hidden_len, pkg, pkg_len, vn, vn_len, vc, vc_len, label, label_len, fb, fb_len, (const uint8_t*)post_ptr, post_len, (const uint8_t*)xk_ptr, xk_len, outer) == 0) {
            if (probe_outer_to_mian_c(ct_ptr, ct_len, outer, hidden, hidden_len, fb, fb_len, (const uint8_t*)post_ptr, post_len, (const uint8_t*)xk_ptr, xk_len, main_name, main_len, max_main)) { *found_index = idx; return 1; }
        }
        idx += direction;
    }
    return 0;
}


// v100 broad C enum core: evaluate the common/native/template outer formulas
// inside C, then decrypt and gate mian.iyu inside C before returning a hit.
typedef struct { const uint8_t *p; int n; } iapt_bs;
static int bs_eq(iapt_bs a, iapt_bs b) { return a.n == b.n && (a.n == 0 || memcmp(a.p, b.p, (size_t)a.n) == 0); }
static int bs_copy(uint8_t *dst, int cap, iapt_bs a) { if (a.n < 0 || a.n > cap) return -1; if (a.n) memcpy(dst, a.p, (size_t)a.n); return a.n; }
static int bs_cat(uint8_t *dst, int cap, iapt_bs a, iapt_bs b) {
    if (a.n < 0 || b.n < 0 || a.n + b.n > cap) return -1;
    if (a.n) memcpy(dst, a.p, (size_t)a.n);
    if (b.n) memcpy(dst + a.n, b.p, (size_t)b.n);
    return a.n + b.n;
}
static int bs_cat3(uint8_t *dst, int cap, iapt_bs a, iapt_bs b, iapt_bs c) {
    int n = bs_cat(dst, cap, a, b); if (n < 0) return -1;
    if (n + c.n > cap) return -1;
    if (c.n) memcpy(dst + n, c.p, (size_t)c.n);
    return n + c.n;
}
static int slky_bs(iapt_bs a, iapt_bs b, const uint8_t *post, int post_len, uint8_t out[16]) {
    if (a.p && b.p && a.n == 16 && b.n == 16)
        return iapp_slky_16_16(a.p, b.p, post, post_len, out);
    return iapp_slky_core(a.p, a.n, b.p, b.n, post, post_len, out);
}
static int outer_probe_seed(const void *ct_ptr, size_t ct_len, const uint8_t seed[16], int transform_xor,
        const uint8_t *hidden, int hidden_len, const char *fb, int fb_len,
        const uint8_t *post, int post_len, const uint8_t *xk, int xk_len,
        const char *main_name, int main_len, size_t max_main) {
    uint8_t outer[16];
    if (transform_xor) xor_repeat16(seed, xk, xk_len, outer);
    else memcpy(outer, seed, 16);
    return probe_outer_to_mian_c(ct_ptr, ct_len, outer, hidden, hidden_len, fb, fb_len, post, post_len, xk, xk_len, main_name, main_len, max_main);
}
static int p25_probe(const void *ct_ptr, size_t ct_len, iapt_bs first, iapt_bs second, int use_post, int transform_xor,
        const uint8_t *hidden, int hidden_len, const char *fb, int fb_len,
        const uint8_t *post, int post_len, const uint8_t *xk, int xk_len,
        const char *main_name, int main_len, size_t max_main) {
    uint8_t p19[16], p24[16], p25[16];
    const uint8_t *pk = use_post ? post : NULL;
    int pklen = use_post ? post_len : 0;
    if (slky_bs(first, second, pk, pklen, p19) != 0) return 0;
    iapt_bs bp19 = {p19, 16};
    if (slky_bs(bp19, bp19, pk, pklen, p24) != 0) return 0;
    iapt_bs bp24 = {p24, 16};
    if (slky_bs(bp19, bp24, pk, pklen, p25) != 0) return 0;
    return outer_probe_seed(ct_ptr, ct_len, p25, transform_xor, hidden, hidden_len, fb, fb_len, post, post_len, xk, xk_len, main_name, main_len, max_main);
}
static int seed_slky_probe(const void *ct_ptr, size_t ct_len, iapt_bs a, iapt_bs b, int use_post, int transform_xor,
        const uint8_t *hidden, int hidden_len, const char *fb, int fb_len,
        const uint8_t *post, int post_len, const uint8_t *xk, int xk_len,
        const char *main_name, int main_len, size_t max_main) {
    uint8_t seed[16];
    const uint8_t *pk = use_post ? post : NULL;
    int pklen = use_post ? post_len : 0;
    if (slky_bs(a, b, pk, pklen, seed) != 0) return 0;
    return outer_probe_seed(ct_ptr, ct_len, seed, transform_xor, hidden, hidden_len, fb, fb_len, post, post_len, xk, xk_len, main_name, main_len, max_main);
}
static int idbfj_p19_probe(const void *ct_ptr, size_t ct_len, iapt_bs input, iapt_bs base, iapt_bs hidden_bs,
        iapt_bs versionName, iapt_bs package, iapt_bs appLabel, iapt_bs versionCode, iapt_bs fb_bs,
        iapt_bs signature, int sig_variant,
        const uint8_t *hidden, int hidden_len, const char *fb, int fb_len,
        const uint8_t *post, int post_len, const uint8_t *xk, int xk_len,
        const char *main_name, int main_len, size_t max_main) {
    uint8_t first_buf[2048];
    iapt_bs first;
    if (bs_eq(input, hidden_bs)) first = base;
    else {
        int n = bs_cat(first_buf, (int)sizeof(first_buf), base, input);
        if (n < 0) return 0;
        first.p = first_buf; first.n = n;
    }
    int signed_sum = first.n;
    for (int i = 0; i < first.n; i++) signed_sum += s8c(first.p[i]);
    int v = signed_sum + s8c(first.p[0]) * s8c(first.p[first.n - 1]);
    int pick = v - c_divc(v, 6) * 6;
    if (pick < 0 || pick > 5) return 0;
    iapt_bs seconds[6] = {versionName, package, appLabel, versionCode, hidden_bs, fb_bs};
    uint8_t p19[16], p24[16], p25[16];
    if (slky_bs(first, seconds[pick], post, post_len, p19) != 0) return 0;
    iapt_bs bp19 = {p19, 16};
    if (sig_variant) {
        if (!signature.p || signature.n <= 0) return 0;
        if (slky_bs(signature, bp19, post, post_len, p24) != 0) return 0;
    } else {
        if (slky_bs(bp19, bp19, post, post_len, p24) != 0) return 0;
    }
    iapt_bs bp24 = {p24, 16};
    if (slky_bs(bp19, bp24, post, post_len, p25) != 0) return 0;
    return outer_probe_seed(ct_ptr, ct_len, p25, 1, hidden, hidden_len, fb, fb_len, post, post_len, xk, xk_len, main_name, main_len, max_main);
}
static int broad_try_one(const void *ct_ptr, size_t ct_len,
        const uint8_t *hidden, int hidden_len,
        const char *pkg, int pkg_len, const char *vn, int vn_len,
        const char *vc, int vc_len, const char *label, int label_len,
        const char *fb, int fb_len, const void *sig_ptr, int sig_len, const void *jg_ptr, int jg_len,
        const void *post_ptr, int post_len, const void *xk_ptr, int xk_len,
        const char *main_name, int main_len, size_t max_main, int *alg_id) {
    const uint8_t *post = (const uint8_t*)post_ptr; const uint8_t *xk = (const uint8_t*)xk_ptr;
    iapt_bs hidden_bs={(const uint8_t*)hidden, hidden_len}, pkg_bs={(const uint8_t*)pkg,pkg_len}, vn_bs={(const uint8_t*)vn,vn_len}, vc_bs={(const uint8_t*)vc,vc_len}, label_bs={(const uint8_t*)label,label_len}, fb_bs={(const uint8_t*)fb,fb_len};
    static const uint8_t empty_s[1] = {0};
    iapt_bs empty_bs={empty_s,0}, mian_bs={(const uint8_t*)"mian.iyu",8}, dot_bs={(const uint8_t*)".mjs",4}, lib_bs={(const uint8_t*)"lib.so",6};
    iapt_bs sig_bs={(const uint8_t*)sig_ptr, sig_len}, jg_bs={(const uint8_t*)jg_ptr, jg_len};
    uint8_t hidden_fb_buf[256], fb_hidden_buf[256], base_tail_buf[1024], base_buf[1536], base_no_fb_buf[1024], meta_no_hidden_buf[1024];
    int n_hidden_fb = bs_cat(hidden_fb_buf, sizeof(hidden_fb_buf), hidden_bs, fb_bs);
    int n_fb_hidden = bs_cat(fb_hidden_buf, sizeof(fb_hidden_buf), fb_bs, hidden_bs);
    int n_tail = 0;
    if (vn_len + pkg_len + label_len + vc_len + fb_len > (int)sizeof(base_tail_buf)) return 0;
    memcpy(base_tail_buf+n_tail, vn, vn_len); n_tail+=vn_len; memcpy(base_tail_buf+n_tail, pkg, pkg_len); n_tail+=pkg_len; memcpy(base_tail_buf+n_tail, label, label_len); n_tail+=label_len; memcpy(base_tail_buf+n_tail, vc, vc_len); n_tail+=vc_len; memcpy(base_tail_buf+n_tail, fb, fb_len); n_tail+=fb_len;
    iapt_bs base_tail={base_tail_buf,n_tail};
    int n_base = bs_cat(base_buf, sizeof(base_buf), hidden_bs, base_tail);
    if (n_base < 0 || n_hidden_fb < 0 || n_fb_hidden < 0) return 0;
    iapt_bs base={base_buf,n_base};
    int n_meta = n_tail;
    memcpy(meta_no_hidden_buf, base_tail_buf, (size_t)n_tail);
    iapt_bs meta_no_hidden={meta_no_hidden_buf,n_meta};
    int n_base_no_fb=0;
    if (hidden_len + vn_len + pkg_len + label_len + vc_len > (int)sizeof(base_no_fb_buf)) return 0;
    memcpy(base_no_fb_buf+n_base_no_fb, hidden, hidden_len); n_base_no_fb+=hidden_len; memcpy(base_no_fb_buf+n_base_no_fb, vn, vn_len); n_base_no_fb+=vn_len; memcpy(base_no_fb_buf+n_base_no_fb, pkg, pkg_len); n_base_no_fb+=pkg_len; memcpy(base_no_fb_buf+n_base_no_fb, label, label_len); n_base_no_fb+=label_len; memcpy(base_no_fb_buf+n_base_no_fb, vc, vc_len); n_base_no_fb+=vc_len;
    iapt_bs base_no_fb={base_no_fb_buf,n_base_no_fb};
    iapt_bs hidden_fb={hidden_fb_buf,n_hidden_fb}, fb_hidden={fb_hidden_buf,n_fb_hidden};
    iapt_bs firsts[7] = {base, base_tail, base_no_fb, meta_no_hidden, hidden_bs, hidden_fb, fb_hidden};
    iapt_bs seconds[8] = {vn_bs, pkg_bs, label_bs, vc_bs, fb_bs, hidden_bs, base_tail, base};

    int alg=1;
    if (p25_probe(ct_ptr, ct_len, base, hidden_bs, 1, 1, hidden, hidden_len, fb, fb_len, post, post_len, xk, xk_len, main_name, main_len, max_main)) { if(alg_id)*alg_id=alg; return 1; }
    alg++;
    if (sig_len > 0) {
        uint8_t p19[16], p24[16], p25[16];
        if (slky_bs(base, hidden_bs, post, post_len, p19)==0) { iapt_bs bp19={p19,16}; if (slky_bs(sig_bs,bp19,post,post_len,p24)==0) { iapt_bs bp24={p24,16}; if (slky_bs(bp19,bp24,post,post_len,p25)==0 && outer_probe_seed(ct_ptr,ct_len,p25,1,hidden,hidden_len,fb,fb_len,post,post_len,xk,xk_len,main_name,main_len,max_main)) { if(alg_id)*alg_id=alg; return 1; } } }
    }
    alg++;
    for (int s=0;s<5;s++,alg++) if (p25_probe(ct_ptr, ct_len, base, seconds[s], 1, 1, hidden, hidden_len, fb, fb_len, post, post_len, xk, xk_len, main_name, main_len, max_main)) { if(alg_id)*alg_id=alg; return 1; }
    for (int i=0;i<7;i++) for (int j=0;j<8;j++,alg++) {
        if (p25_probe(ct_ptr, ct_len, firsts[i], seconds[j], 0, 0, hidden, hidden_len, fb, fb_len, post, post_len, xk, xk_len, main_name, main_len, max_main)) { if(alg_id)*alg_id=alg; return 1; }
        alg++;
        if (p25_probe(ct_ptr, ct_len, firsts[i], seconds[j], 1, 1, hidden, hidden_len, fb, fb_len, post, post_len, xk, xk_len, main_name, main_len, max_main)) { if(alg_id)*alg_id=alg; return 1; }
    }
    iapt_bs inputs[8] = {hidden_bs, jg_bs, mian_bs, empty_bs, pkg_bs, label_bs, lib_bs, dot_bs};
    for (int i=0;i<8;i++,alg++) {
        if (idbfj_p19_probe(ct_ptr, ct_len, inputs[i], base, hidden_bs, vn_bs, pkg_bs, label_bs, vc_bs, fb_bs, sig_bs, 0, hidden, hidden_len, fb, fb_len, post, post_len, xk, xk_len, main_name, main_len, max_main)) { if(alg_id)*alg_id=alg; return 1; }
        alg++;
        if (sig_len > 0 && idbfj_p19_probe(ct_ptr, ct_len, inputs[i], base, hidden_bs, vn_bs, pkg_bs, label_bs, vc_bs, fb_bs, sig_bs, 1, hidden, hidden_len, fb, fb_len, post, post_len, xk, xk_len, main_name, main_len, max_main)) { if(alg_id)*alg_id=alg; return 1; }
    }
    // A compact subset of concat-before-slky templates that previously fixed x86 burden1a.
    iapt_bs concat_pairs_a[5] = {hidden_bs, base_tail, base, hidden_bs, base_no_fb};
    iapt_bs concat_pairs_b[5] = {base_tail, hidden_bs, hidden_bs, base, hidden_bs};
    uint8_t joined[2048];
    for (int i=0;i<5;i++) {
        int n = bs_cat(joined, sizeof(joined), concat_pairs_a[i], concat_pairs_b[i]);
        if (n > 0) {
            iapt_bs jn={joined,n};
            if (seed_slky_probe(ct_ptr, ct_len, jn, concat_pairs_a[i], 1, 1, hidden, hidden_len, fb, fb_len, post, post_len, xk, xk_len, main_name, main_len, max_main)) { if(alg_id)*alg_id=alg; return 1; } alg++;
            if (seed_slky_probe(ct_ptr, ct_len, jn, concat_pairs_b[i], 1, 1, hidden, hidden_len, fb, fb_len, post, post_len, xk, xk_len, main_name, main_len, max_main)) { if(alg_id)*alg_id=alg; return 1; } alg++;
            if (seed_slky_probe(ct_ptr, ct_len, concat_pairs_a[i], concat_pairs_b[i], 1, 1, hidden, hidden_len, fb, fb_len, post, post_len, xk, xk_len, main_name, main_len, max_main)) { if(alg_id)*alg_id=alg; return 1; } alg++;
        }
    }
    return 0;
}

int iapp_broad_dexkey_scan_mian(const void *ct_ptr, size_t ct_len,
        const void *hidden_ptr, int hidden_len,
        const char *pkg, int pkg_len, const char *vn, int vn_len,
        const char *vc, int vc_len, const char *label, int label_len,
        const void *sig_ptr, int sig_len, const void *jg_ptr, int jg_len,
        int start_fb, int stop_fb, int direction,
        const void *post_ptr, int post_len, const void *xk_ptr, int xk_len,
        const char *main_name, int main_len, size_t max_main, int *found_fb, int *found_alg) {
    if (!ct_ptr || !hidden_ptr || !post_ptr || !xk_ptr || !main_name || !found_fb) return -1;
    if (direction == 0) direction = (start_fb <= stop_fb) ? 1 : -1;
    int fbv = start_fb;
    char fb_buf[32];
    while ((direction > 0 && fbv <= stop_fb) || (direction < 0 && fbv >= stop_fb)) {
        int fb_len = iapt_i32_ascii(fbv, fb_buf);
        int alg = 0;
        if (fb_len > 0 && fb_len < (int)sizeof(fb_buf)) {
            if (broad_try_one(ct_ptr, ct_len, (const uint8_t*)hidden_ptr, hidden_len, pkg, pkg_len, vn, vn_len, vc, vc_len, label, label_len, fb_buf, fb_len, sig_ptr, sig_len, jg_ptr, jg_len, post_ptr, post_len, xk_ptr, xk_len, main_name, main_len, max_main, &alg)) { *found_fb = fbv; if(found_alg)*found_alg=alg; return 1; }
        }
        fbv += direction;
    }
    return 0;
}


static inline void iapt_md5_store_ctx(const MD5_CTX *ctx, uint8_t out[16]) {
    uint32_t v[4]={(uint32_t)ctx->A,(uint32_t)ctx->B,(uint32_t)ctx->C,(uint32_t)ctx->D};
    for(int j=0;j<4;j++){out[j*4]=(uint8_t)v[j];out[j*4+1]=(uint8_t)(v[j]>>8);out[j*4+2]=(uint8_t)(v[j]>>16);out[j*4+3]=(uint8_t)(v[j]>>24);}
}

typedef uint32_t iapt_v4u __attribute__((vector_size(16)));
static const uint32_t iapt_md5x_k[64]={
0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391};
static const uint8_t iapt_md5x_s[64]={7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,4,11,16,23,4,11,16,23,4,11,16,23,
4,11,16,23,6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21};
static inline uint32_t iapt_ld32(const uint8_t*p){return(uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static inline iapt_v4u iapt_vrol(iapt_v4u x,int n){return(x<<n)|(x>>(32-n));}
static inline void iapt_md5x4_comp(iapt_v4u st[4],const uint8_t blocks[4][192],int off){
    iapt_v4u m[16];
    for(int j=0;j<16;j++)m[j]=(iapt_v4u){iapt_ld32(blocks[0]+off+4*j),iapt_ld32(blocks[1]+off+4*j),iapt_ld32(blocks[2]+off+4*j),iapt_ld32(blocks[3]+off+4*j)};
    iapt_v4u a=st[0],b=st[1],c=st[2],d=st[3];
    for(int i=0;i<64;i++){iapt_v4u f;int g;if(i<16){f=(b&c)|((~b)&d);g=i;}else if(i<32){f=(d&b)|((~d)&c);g=(5*i+1)&15;}else if(i<48){f=b^c^d;g=(3*i+5)&15;}else{f=c^(b|(~d));g=(7*i)&15;}iapt_v4u t=d;d=c;c=b;iapt_v4u kv={iapt_md5x_k[i],iapt_md5x_k[i],iapt_md5x_k[i],iapt_md5x_k[i]};b=b+iapt_vrol(a+f+kv+m[g],iapt_md5x_s[i]);a=t;}
    st[0]+=a;st[1]+=b;st[2]+=c;st[3]+=d;
}
static inline int iapt_md5x4_messages(uint8_t msgs[4][192],const int lens[4],uint8_t out[4][16]){
    int totals[4];for(int l=0;l<4;l++){if(lens[l]<0||lens[l]>183)return-1;totals[l]=lens[l]<56?64:(lens[l]<120?128:192);}
    for(int want=64;want<=192;want+=64){int ids[4],n=0;for(int l=0;l<4;l++)if(totals[l]==want)ids[n++]=l;if(!n)continue;
        uint8_t blocks[4][192];for(int v=0;v<4;v++){int l=ids[v<n?v:0];memset(blocks[v],0,(size_t)want);memcpy(blocks[v],msgs[l],(size_t)lens[l]);blocks[v][lens[l]]=0x80;uint64_t bits=(uint64_t)lens[l]*8u;for(int i=0;i<8;i++)blocks[v][want-8+i]=(uint8_t)(bits>>(8*i));}
        iapt_v4u st[4]={(iapt_v4u){0x67452301,0x67452301,0x67452301,0x67452301},(iapt_v4u){0xefcdab89,0xefcdab89,0xefcdab89,0xefcdab89},(iapt_v4u){0x98badcfe,0x98badcfe,0x98badcfe,0x98badcfe},(iapt_v4u){0x10325476,0x10325476,0x10325476,0x10325476}};
        iapt_md5x4_comp(st,blocks,0);if(want>=128)iapt_md5x4_comp(st,blocks,64);if(want>=192)iapt_md5x4_comp(st,blocks,128);
        for(int v=0;v<n;v++){int l=ids[v];for(int j=0;j<4;j++){uint32_t x=st[j][v];out[l][j*4]=(uint8_t)x;out[l][j*4+1]=(uint8_t)(x>>8);out[l][j*4+2]=(uint8_t)(x>>16);out[l][j*4+3]=(uint8_t)(x>>24);}}
    }return 0;
}
static inline int iapt_build_slky_msg_parts(const uint8_t*prefix,int prefix_len,const char*fb,int fb_len,const uint8_t*suffix,int suffix_len,const uint8_t*b,int b_len,int signed_sum,int first_s8,int last_s8,uint8_t msg[192],int*c2){
    int a_len=prefix_len+fb_len+suffix_len;int avg=signed_sum/a_len;int mix=(signed_sum+first_s8*last_s8)/a_len;int rem=signed_sum%a_len;char mb[16];int ml=iapt_i32_ascii(mix,mb);int total=a_len+ml+b_len;if(total>183)return-1;uint8_t mask=(uint8_t)avg;int p=0;for(int i=0;i<prefix_len;i++)msg[p++]=prefix[i]^mask;for(int i=0;i<fb_len;i++)msg[p++]=(uint8_t)fb[i]^mask;for(int i=0;i<suffix_len;i++)msg[p++]=suffix[i]^mask;for(int i=0;i<ml;i++)msg[p++]=(uint8_t)mb[i]^mask;for(int i=0;i<b_len;i++)msg[p++]=b[i]^mask;*c2=rem+b_len;return total;
}
static inline int iapt_build_slky16_msg(const uint8_t a[16],const uint8_t b[16],uint8_t msg[192],int*c2){int ss=16;for(int i=0;i<16;i++)ss+=s8c(a[i]);int avg=ss/16;int mix=(ss+s8c(a[0])*s8c(a[15]))/16;int rem=ss%16;char mb[16];int ml=iapt_i32_ascii(mix,mb);uint8_t mask=(uint8_t)avg;int p=0;for(int i=0;i<16;i++)msg[p++]=a[i]^mask;for(int i=0;i<ml;i++)msg[p++]=(uint8_t)mb[i]^mask;for(int i=0;i<16;i++)msg[p++]=b[i]^mask;*c2=rem+16;return p;}

/* Exact SLKY for a = fixed_prefix || fb_ascii || fixed_suffix with the
 * signed sum already known.  This removes two repeated scans and all temporary
 * base/first concatenations from the idbfj hot loop. */
static inline int iapp_slky_parts_precalc(
        const uint8_t *prefix, int prefix_len, const char *fb, int fb_len,
        const uint8_t *suffix, int suffix_len,
        const uint8_t *b, int b_len,
        int signed_sum, int first_s8, int last_s8,
        const uint8_t *post, int post_len,
        MD5_CTX prefix_states[256], uint8_t prefix_state_valid[256],
        uint8_t out[16]) {
    const int a_len = prefix_len + fb_len + suffix_len;
    if (!prefix || prefix_len <= 0 || !fb || fb_len <= 0 || a_len <= 0) return -1;
    const int has_b = b && b_len > 0;
    const int avg = signed_sum / a_len;
    const int mix = (signed_sum + first_s8 * last_s8) / a_len;
    const int remainder = signed_sum % a_len;
    char mixbuf[16];
    const int mixlen = iapt_i32_ascii(mix, mixbuf);
    const int total = a_len + mixlen + (has_b ? b_len : 0);
    uint8_t stackbuf[512];
    uint8_t *buf = stackbuf;
    if (total > (int)sizeof(stackbuf)) {
        buf = (uint8_t*)malloc((size_t)total);
        if (!buf) return -2;
    }
    const uint8_t mask = (uint8_t)avg;
    int pos=0;
    for(int i=0;i<prefix_len;i++) buf[pos++]=(uint8_t)(prefix[i]^mask);
    for(int i=0;i<fb_len;i++) buf[pos++]=(uint8_t)(((uint8_t)fb[i])^mask);
    for(int i=0;i<suffix_len;i++) buf[pos++]=(uint8_t)(suffix[i]^mask);
    for(int i=0;i<mixlen;i++) buf[pos++]=(uint8_t)(((uint8_t)mixbuf[i])^mask);
    if(has_b) for(int i=0;i<b_len;i++) buf[pos++]=(uint8_t)(b[i]^mask);
    uint8_t digest[16];
    int md5_done=0;
    /* The first 64 bytes are fixed prefix bytes under a one-byte XOR mask.
     * Cache the optimized OpenSSL MD5 transform state for each observed mask. */
    if(prefix_len>=64 && total>=64 && total<120 && prefix_states && prefix_state_valid) {
        const unsigned mi=(unsigned)mask;
        if(!prefix_state_valid[mi]) {
            uint8_t first_block[64];
            for(int i=0;i<64;i++) first_block[i]=(uint8_t)(prefix[i]^mask);
            MD5_Init(&prefix_states[mi]);
            MD5_Transform(&prefix_states[mi],first_block);
            prefix_state_valid[mi]=1;
        }
        uint8_t last_block[64]; memset(last_block,0,64);
        const int rem=total-64;
        memcpy(last_block,buf+64,(size_t)rem);
        last_block[rem]=0x80;
        uint64_t bits=(uint64_t)total*8u;
        for(int i=0;i<8;i++) last_block[56+i]=(uint8_t)(bits>>(8*i));
        MD5_CTX ctx=prefix_states[mi];
        MD5_Transform(&ctx,last_block);
        iapt_md5_store_ctx(&ctx,digest);
        md5_done=1;
    }
    if(!md5_done) MD5(buf,(size_t)total,digest);
    if(buf!=stackbuf) free(buf);
    iapt_slky_post_transform(digest,remainder+(has_b?b_len:0),post,post_len);
    memcpy(out,digest,16);
    return 0;
}


/* v128: precompute slky(fixed_long_a, variable_16_b).  Signature bytes,
 * signed sum, xor mask, mix text, and all complete MD5 prefix blocks are
 * invariant across every dexkey/sokey candidate. */
typedef struct { MD5_CTX base; uint8_t mask; int c2; int ready; } iapt_slky_fixed_a16_prep;
static int iapt_slky_fixed_a16_prepare(const uint8_t *a,int an,iapt_slky_fixed_a16_prep *p){
    if(!a||an<=0||!p)return-1;int ss=an;for(int i=0;i<an;i++)ss+=s8c(a[i]);
    int avg=c_divc(ss,an),rem=ss-avg*an,mix=c_divc(ss+s8c(a[0])*s8c(a[an-1]),an);
    char mb[24];int mn=iapt_i32_ascii(mix,mb);size_t n=(size_t)an+(size_t)mn;
    uint8_t stack[2048],*buf=stack;if(n>sizeof(stack)){buf=(uint8_t*)malloc(n);if(!buf)return-2;}
    uint8_t mask=(uint8_t)avg;for(int i=0;i<an;i++)buf[i]=a[i]^mask;for(int i=0;i<mn;i++)buf[an+i]=(uint8_t)mb[i]^mask;
    MD5_Init(&p->base);MD5_Update(&p->base,buf,n);if(buf!=stack)free(buf);
    p->mask=mask;p->c2=rem+16+8;p->ready=1;return 0;
}
static int iapt_slky_fixed_a16_apply(const iapt_slky_fixed_a16_prep *p,const uint8_t b[16],const uint8_t *post,int post_len,uint8_t out[16]){
    if(!p||!p->ready||!b||!out)return-1;uint8_t xb[16];for(int i=0;i<16;i++)xb[i]=b[i]^p->mask;
    MD5_CTX ctx=p->base;MD5_Update(&ctx,xb,16);MD5_Final(out,&ctx);iapt_slky_post_transform(out,p->c2-8,post,post_len);return 0;
}

// v107: specialized x86 idbfj dexkey scanner for password/signature samples.
// This keeps the hot loop in C and tests only the two observed burden1b shapes
// instead of the hundreds of generic broad formulas.
static int iapp_idbfj_nosig_scan_x4(const void *ct_ptr,size_t ct_len,const uint8_t*hidden,int hidden_len,const char*pkg,int pkg_len,const char*vn,int vn_len,const char*vc,int vc_len,const char*label,int label_len,const uint8_t*input,int input_len,int start_fb,int stop_fb,int direction,const uint8_t*post,int post_len,const uint8_t*xk,int xk_len,const char*main_name,int main_len,size_t max_main,int*found_fb){
    uint8_t prefix[1536];int prefix_len=0;if(hidden_len+vn_len+pkg_len+label_len+vc_len>(int)sizeof(prefix))return-2;memcpy(prefix+prefix_len,hidden,hidden_len);prefix_len+=hidden_len;if(vn_len){memcpy(prefix+prefix_len,vn,vn_len);prefix_len+=vn_len;}if(pkg_len){memcpy(prefix+prefix_len,pkg,pkg_len);prefix_len+=pkg_len;}if(label_len){memcpy(prefix+prefix_len,label,label_len);prefix_len+=label_len;}if(vc_len){memcpy(prefix+prefix_len,vc,vc_len);prefix_len+=vc_len;}
    int input_is_hidden=input_len==hidden_len&&memcmp(input,hidden,hidden_len)==0;const uint8_t*suf=input_is_hidden?NULL:input;int suf_len=input_is_hidden?0:input_len;int fixed=prefix_len+suf_len;for(int i=0;i<prefix_len;i++)fixed+=s8c(prefix[i]);for(int i=0;i<suf_len;i++)fixed+=s8c(suf[i]);int first=s8c(prefix[0]);iapt_bs sec[5]={{(const uint8_t*)vn,vn_len},{(const uint8_t*)pkg,pkg_len},{(const uint8_t*)label,label_len},{(const uint8_t*)vc,vc_len},{hidden,hidden_len}};
    int fbv=start_fb;while((direction>0&&fbv<=stop_fb)||(direction<0&&fbv>=stop_fb)){
        int count=0,vals[4],fl[4],ss[4],last[4],c2[4],lens[4];char fbs[4][16];uint8_t msgs[4][192],p19[4][16];
        for(int l=0;l<4;l++){int v=fbv+direction*l;if((direction>0&&v>stop_fb)||(direction<0&&v<stop_fb))break;vals[l]=v;fl[l]=iapt_i32_ascii(v,fbs[l]);int ds=0;for(int i=0;i<fl[l];i++)ds+=(uint8_t)fbs[l][i];ss[l]=fixed+fl[l]+ds;last[l]=suf_len?s8c(suf[suf_len-1]):s8c((uint8_t)fbs[l][fl[l]-1]);int q=ss[l]+first*last[l];int pick=q-c_divc(q,6)*6;const uint8_t*second;int sn;if(pick==5){second=(const uint8_t*)fbs[l];sn=fl[l];}else if(pick>=0&&pick<5){second=sec[pick].p;sn=sec[pick].n;}else return-3;lens[l]=iapt_build_slky_msg_parts(prefix,prefix_len,fbs[l],fl[l],suf,suf_len,second,sn,ss[l],first,last[l],msgs[l],&c2[l]);if(lens[l]<56||lens[l]>183)return-4;count++;}
        for(int l=count;l<4;l++){memcpy(msgs[l],msgs[0],lens[0]);lens[l]=lens[0];c2[l]=c2[0];}
        if(iapt_md5x4_messages(msgs,lens,p19)!=0)return-5;for(int l=0;l<count;l++)iapt_slky_post_transform(p19[l],c2[l],post,post_len);
        uint8_t p24[4][16],p25[4][16];int l24[4],c24[4];for(int l=0;l<4;l++)l24[l]=iapt_build_slky16_msg(p19[l],p19[l],msgs[l],&c24[l]);if(iapt_md5x4_messages(msgs,l24,p24)!=0)return-6;for(int l=0;l<4;l++)iapt_slky_post_transform(p24[l],c24[l],post,post_len);
        int l25[4],c25[4];for(int l=0;l<4;l++)l25[l]=iapt_build_slky16_msg(p19[l],p24[l],msgs[l],&c25[l]);if(iapt_md5x4_messages(msgs,l25,p25)!=0)return-7;for(int l=0;l<4;l++)iapt_slky_post_transform(p25[l],c25[l],post,post_len);
        for(int l=0;l<count;l++){uint8_t outer[16];xor_repeat16(p25[l],xk,xk_len,outer);if(probe_outer_to_mian_c(ct_ptr,ct_len,outer,hidden,hidden_len,fbs[l],fl[l],post,post_len,xk,xk_len,main_name,main_len,max_main)){*found_fb=vals[l];return 1;}}
        fbv+=direction*count;
    }return 0;
}


static int iapp_idbfj_sig_scan_x4(const void *ct_ptr,size_t ct_len,const uint8_t*hidden,int hidden_len,const char*pkg,int pkg_len,const char*vn,int vn_len,const char*vc,int vc_len,const char*label,int label_len,const uint8_t*input,int input_len,const uint8_t*sig,int sig_len,int start_fb,int stop_fb,int direction,const uint8_t*post,int post_len,const uint8_t*xk,int xk_len,const char*main_name,int main_len,size_t max_main,int*found_fb){
    if(!sig||sig_len<=0)return 0;iapt_slky_fixed_a16_prep sp;memset(&sp,0,sizeof(sp));if(iapt_slky_fixed_a16_prepare(sig,sig_len,&sp)!=0)return-2;
    uint8_t prefix[1536];int prefix_len=0;if(hidden_len+vn_len+pkg_len+label_len+vc_len>(int)sizeof(prefix))return-3;memcpy(prefix+prefix_len,hidden,hidden_len);prefix_len+=hidden_len;if(vn_len){memcpy(prefix+prefix_len,vn,vn_len);prefix_len+=vn_len;}if(pkg_len){memcpy(prefix+prefix_len,pkg,pkg_len);prefix_len+=pkg_len;}if(label_len){memcpy(prefix+prefix_len,label,label_len);prefix_len+=label_len;}if(vc_len){memcpy(prefix+prefix_len,vc,vc_len);prefix_len+=vc_len;}
    int input_is_hidden=input_len==hidden_len&&memcmp(input,hidden,hidden_len)==0;const uint8_t*suf=input_is_hidden?NULL:input;int suf_len=input_is_hidden?0:input_len;int fixed=prefix_len+suf_len;for(int i=0;i<prefix_len;i++)fixed+=s8c(prefix[i]);for(int i=0;i<suf_len;i++)fixed+=s8c(suf[i]);int first=s8c(prefix[0]);iapt_bs sec[5]={{(const uint8_t*)vn,vn_len},{(const uint8_t*)pkg,pkg_len},{(const uint8_t*)label,label_len},{(const uint8_t*)vc,vc_len},{hidden,hidden_len}};
    int fbv=start_fb;while((direction>0&&fbv<=stop_fb)||(direction<0&&fbv>=stop_fb)){
        int count=0,vals[4],fl[4],ss[4],last[4],c2[4],lens[4];char fbs[4][16];uint8_t msgs[4][192],p19[4][16];
        for(int l=0;l<4;l++){int v=fbv+direction*l;if((direction>0&&v>stop_fb)||(direction<0&&v<stop_fb))break;vals[l]=v;fl[l]=iapt_i32_ascii(v,fbs[l]);int ds=0;for(int i=0;i<fl[l];i++)ds+=(uint8_t)fbs[l][i];ss[l]=fixed+fl[l]+ds;last[l]=suf_len?s8c(suf[suf_len-1]):s8c((uint8_t)fbs[l][fl[l]-1]);int q=ss[l]+first*last[l];int pick=q-c_divc(q,6)*6;const uint8_t*second;int sn;if(pick==5){second=(const uint8_t*)fbs[l];sn=fl[l];}else if(pick>=0&&pick<5){second=sec[pick].p;sn=sec[pick].n;}else return-4;lens[l]=iapt_build_slky_msg_parts(prefix,prefix_len,fbs[l],fl[l],suf,suf_len,second,sn,ss[l],first,last[l],msgs[l],&c2[l]);if(lens[l]<56||lens[l]>183)return-5;count++;}
        for(int l=count;l<4;l++){memcpy(msgs[l],msgs[0],lens[0]);lens[l]=lens[0];c2[l]=c2[0];}
        if(iapt_md5x4_messages(msgs,lens,p19)!=0)return-6;for(int l=0;l<count;l++)iapt_slky_post_transform(p19[l],c2[l],post,post_len);
        uint8_t p24[4][16],p25[4][16];for(int l=0;l<4;l++)if(iapt_slky_fixed_a16_apply(&sp,p19[l],post,post_len,p24[l])!=0)return-7;
        int l25[4],c25[4];for(int l=0;l<4;l++)l25[l]=iapt_build_slky16_msg(p19[l],p24[l],msgs[l],&c25[l]);if(iapt_md5x4_messages(msgs,l25,p25)!=0)return-8;for(int l=0;l<4;l++)iapt_slky_post_transform(p25[l],c25[l],post,post_len);
        for(int l=0;l<count;l++){uint8_t outer[16];xor_repeat16(p25[l],xk,xk_len,outer);if(probe_outer_to_mian_c(ct_ptr,ct_len,outer,hidden,hidden_len,fbs[l],fl[l],post,post_len,xk,xk_len,main_name,main_len,max_main)){*found_fb=vals[l];return 1;}}
        fbv+=direction*count;
    }return 0;
}

int iapp_idbfj_dexkey_scan_mian(const void *ct_ptr, size_t ct_len,
        const void *hidden_ptr, int hidden_len,
        const char *pkg, int pkg_len, const char *vn, int vn_len,
        const char *vc, int vc_len, const char *label, int label_len,
        const void *input_ptr, int input_len, const void *sig_ptr, int sig_len,
        int start_fb, int stop_fb, int direction,
        const void *post_ptr, int post_len, const void *xk_ptr, int xk_len,
        const char *main_name, int main_len, size_t max_main,
        int *found_fb, int *found_variant) {
    if (!ct_ptr || !hidden_ptr || !input_ptr || input_len <= 0 || !post_ptr || !xk_ptr || !main_name || !found_fb) return -1;
    if (direction == 0) direction = (start_fb <= stop_fb) ? 1 : -1;
    if(iapt_idbfj_variant_mode==0){int r=iapp_idbfj_nosig_scan_x4(ct_ptr,ct_len,(const uint8_t*)hidden_ptr,hidden_len,pkg,pkg_len,vn,vn_len,vc,vc_len,label,label_len,(const uint8_t*)input_ptr,input_len,start_fb,stop_fb,direction,(const uint8_t*)post_ptr,post_len,(const uint8_t*)xk_ptr,xk_len,main_name,main_len,max_main,found_fb);if(r==1&&found_variant)*found_variant=0;return r;}
    if(iapt_idbfj_variant_mode==1){int r=iapp_idbfj_sig_scan_x4(ct_ptr,ct_len,(const uint8_t*)hidden_ptr,hidden_len,pkg,pkg_len,vn,vn_len,vc,vc_len,label,label_len,(const uint8_t*)input_ptr,input_len,(const uint8_t*)sig_ptr,sig_len,start_fb,stop_fb,direction,(const uint8_t*)post_ptr,post_len,(const uint8_t*)xk_ptr,xk_len,main_name,main_len,max_main,found_fb);if(r==1&&found_variant)*found_variant=1;return r;}
    const uint8_t *hidden=(const uint8_t*)hidden_ptr;
    const uint8_t *input=(const uint8_t*)input_ptr;
    const uint8_t *post=(const uint8_t*)post_ptr;
    const uint8_t *xk=(const uint8_t*)xk_ptr;
    const uint8_t *sig=(const uint8_t*)sig_ptr;

    /* base = hidden || versionName || package || appLabel || versionCode || fb */
    uint8_t prefix[1536]; int prefix_len=0;
    if(hidden_len+vn_len+pkg_len+label_len+vc_len>(int)sizeof(prefix)) return -2;
    memcpy(prefix+prefix_len,hidden,(size_t)hidden_len); prefix_len+=hidden_len;
    if(vn_len){memcpy(prefix+prefix_len,vn,(size_t)vn_len);prefix_len+=vn_len;}
    if(pkg_len){memcpy(prefix+prefix_len,pkg,(size_t)pkg_len);prefix_len+=pkg_len;}
    if(label_len){memcpy(prefix+prefix_len,label,(size_t)label_len);prefix_len+=label_len;}
    if(vc_len){memcpy(prefix+prefix_len,vc,(size_t)vc_len);prefix_len+=vc_len;}

    const int input_is_hidden = input_len==hidden_len && memcmp(input,hidden,(size_t)hidden_len)==0;
    const uint8_t *suffix = input_is_hidden ? NULL : input;
    const int suffix_len = input_is_hidden ? 0 : input_len;
    int fixed_signed = prefix_len + suffix_len;
    for(int i=0;i<prefix_len;i++) fixed_signed += s8c(prefix[i]);
    for(int i=0;i<suffix_len;i++) fixed_signed += s8c(suffix[i]);
    const int first_s8=s8c(prefix[0]);
    MD5_CTX prefix_states[256];
    uint8_t prefix_state_valid[256]; memset(prefix_state_valid,0,sizeof(prefix_state_valid));

    iapt_bs seconds_const[5]={{(const uint8_t*)vn,vn_len},{(const uint8_t*)pkg,pkg_len},
        {(const uint8_t*)label,label_len},{(const uint8_t*)vc,vc_len},{hidden,hidden_len}};
    iapt_bs sig_bs={sig,sig_len};
    iapt_slky_fixed_a16_prep sigprep;memset(&sigprep,0,sizeof(sigprep));int sigprep_ok=(sig_len>0&&iapt_slky_fixed_a16_prepare(sig,sig_len,&sigprep)==0);
    char fb_buf[16];
    int fbv=start_fb;
    while((direction>0&&fbv<=stop_fb)||(direction<0&&fbv>=stop_fb)) {
        int fb_len=iapt_i32_ascii(fbv,fb_buf);
        if(fb_len>0&&fb_len<(int)sizeof(fb_buf)) {
            int digit_sum=0; for(int i=0;i<fb_len;i++) digit_sum += (uint8_t)fb_buf[i];
            int signed_sum=fixed_signed+fb_len+digit_sum;
            int last_s8=suffix_len?s8c(suffix[suffix_len-1]):s8c((uint8_t)fb_buf[fb_len-1]);
            int v=signed_sum+first_s8*last_s8;
            int pick=v-c_divc(v,6)*6;
            if(pick>=0&&pick<=5) {
                const uint8_t *second; int second_len;
                if(pick==5){second=(const uint8_t*)fb_buf;second_len=fb_len;}
                else {second=seconds_const[pick].p;second_len=seconds_const[pick].n;}
                uint8_t p19[16],p24[16],p25[16],outer[16];
                if(iapp_slky_parts_precalc(prefix,prefix_len,fb_buf,fb_len,suffix,suffix_len,
                        second,second_len,signed_sum,first_s8,last_s8,post,post_len,
                        prefix_states,prefix_state_valid,p19)==0) {
                    iapt_bs bp19={p19,16};
                    if(iapt_idbfj_variant_mode!=0&&sigprep_ok&&
                            iapt_slky_fixed_a16_apply(&sigprep,p19,post,post_len,p24)==0) {
                        if(iapp_slky_16_16(p19,p24,post,post_len,p25)==0) {
                            xor_repeat16(p25,xk,xk_len,outer);
                            if(probe_outer_to_mian_c(ct_ptr,ct_len,outer,hidden,hidden_len,fb_buf,fb_len,
                                    post,post_len,xk,xk_len,main_name,main_len,max_main)) {
                                *found_fb=fbv;if(found_variant)*found_variant=1;return 1;
                            }
                        }
                    }
                    if(iapt_idbfj_variant_mode!=1&&iapp_slky_16_16(p19,p19,post,post_len,p24)==0&&
                            iapp_slky_16_16(p19,p24,post,post_len,p25)==0) {
                        xor_repeat16(p25,xk,xk_len,outer);
                        if(probe_outer_to_mian_c(ct_ptr,ct_len,outer,hidden,hidden_len,fb_buf,fb_len,
                                post,post_len,xk,xk_len,main_name,main_len,max_main)) {
                            *found_fb=fbv;if(found_variant)*found_variant=0;return 1;
                        }
                    }
                }
            }
        }
        fbv+=direction;
    }
    return 0;
}


/* Native lane scheduler: all search lanes run inside one shared library call.
 * This removes Python process startup, APK-buffer copying, Queue traffic and
 * repeated shared-library initialization from the common idbfj fast path. */
typedef struct {
    const void *ct_ptr; size_t ct_len;
    const void *hidden_ptr; int hidden_len;
    const char *pkg; int pkg_len; const char *vn; int vn_len;
    const char *vc; int vc_len; const char *label; int label_len;
    const uint8_t *input_blob; const int *input_off; const int *input_len; int input_count;
    const void *sig_ptr; int sig_len;
    const uint8_t *post_blob; const int *post_off; const int *post_len;
    const uint8_t *xk_blob; const int *xk_off; const int *xk_len; int keyset_count;
    const char *main_name; int main_len; size_t max_main;
    int chunk_size;
    volatile int stop;
    int found_fb, found_variant, found_lane, found_keyset, found_input;
} iapt_native_parallel_shared;

typedef struct {
    iapt_native_parallel_shared *sh;
    int lane_id, start_fb, stop_fb, direction, cpu_id;
} iapt_native_parallel_job;

static void *iapt_native_parallel_worker(void *opaque) {
    iapt_native_parallel_job *j=(iapt_native_parallel_job*)opaque;
    iapt_native_parallel_shared *s=j->sh;
#if defined(__linux__) || defined(__ANDROID__)
    if(j->cpu_id>=0){cpu_set_t cs;CPU_ZERO(&cs);CPU_SET(j->cpu_id,&cs);(void)pthread_setaffinity_np(pthread_self(),sizeof(cs),&cs);}
#endif
    int direction=j->direction ? j->direction : (j->start_fb<=j->stop_fb ? 1 : -1);
    int cur=j->start_fb;
    while(!s->stop && ((direction>0&&cur<=j->stop_fb)||(direction<0&&cur>=j->stop_fb))) {
        int edge = direction>0 ? cur+s->chunk_size-1 : cur-s->chunk_size+1;
        if(direction>0&&edge>j->stop_fb)edge=j->stop_fb;
        if(direction<0&&edge<j->stop_fb)edge=j->stop_fb;
        for(int k=0;k<s->keyset_count&&!s->stop;k++) {
            const uint8_t *post=s->post_blob+s->post_off[k];
            const uint8_t *xk=s->xk_blob+s->xk_off[k];
            for(int q=0;q<s->input_count&&!s->stop;q++) {
                int hit=0,variant=-1;
                const uint8_t *inp=s->input_blob+s->input_off[q];
                int r=iapp_idbfj_dexkey_scan_mian(
                    s->ct_ptr,s->ct_len,s->hidden_ptr,s->hidden_len,
                    s->pkg,s->pkg_len,s->vn,s->vn_len,s->vc,s->vc_len,s->label,s->label_len,
                    inp,s->input_len[q],s->sig_ptr,s->sig_len,
                    cur,edge,direction,post,s->post_len[k],xk,s->xk_len[k],
                    s->main_name,s->main_len,s->max_main,&hit,&variant);
                if(r==1) {
                    if(__sync_bool_compare_and_swap(&s->stop,0,1)) {
                        s->found_fb=hit;s->found_variant=variant;s->found_lane=j->lane_id;
                        s->found_keyset=k;s->found_input=q;
                    }
                    return NULL;
                }
            }
        }
        cur=edge+direction;
    }
    return NULL;
}

int iapp_idbfj_dexkey_scan_mian_parallel(
        const void *ct_ptr,size_t ct_len,const void *hidden_ptr,int hidden_len,
        const char *pkg,int pkg_len,const char *vn,int vn_len,const char *vc,int vc_len,
        const char *label,int label_len,
        const void *input_blob,const int *input_off,const int *input_len,int input_count,
        const void *sig_ptr,int sig_len,
        const int *lane_start,const int *lane_stop,const int *lane_dir,const int *lane_cpu,int lane_count,int chunk_size,
        const void *post_blob,const int *post_off,const int *post_len,
        const void *xk_blob,const int *xk_off,const int *xk_len,int keyset_count,
        const char *main_name,int main_len,size_t max_main,
        int *found_fb,int *found_variant,int *found_lane,int *found_keyset,int *found_input) {
    if(!ct_ptr||!hidden_ptr||!input_blob||!input_off||!input_len||input_count<=0||
       !lane_start||!lane_stop||!lane_dir||lane_count<=0||lane_count>32||
       !post_blob||!post_off||!post_len||!xk_blob||!xk_off||!xk_len||keyset_count<=0||
       !main_name||!found_fb)return -1;
    if(chunk_size<1024)chunk_size=65536;
    iapt_native_parallel_shared sh;memset(&sh,0,sizeof(sh));
    sh.ct_ptr=ct_ptr;sh.ct_len=ct_len;sh.hidden_ptr=hidden_ptr;sh.hidden_len=hidden_len;
    sh.pkg=pkg;sh.pkg_len=pkg_len;sh.vn=vn;sh.vn_len=vn_len;sh.vc=vc;sh.vc_len=vc_len;
    sh.label=label;sh.label_len=label_len;sh.input_blob=(const uint8_t*)input_blob;
    sh.input_off=input_off;sh.input_len=input_len;sh.input_count=input_count;sh.sig_ptr=sig_ptr;sh.sig_len=sig_len;
    sh.post_blob=(const uint8_t*)post_blob;sh.post_off=post_off;sh.post_len=post_len;
    sh.xk_blob=(const uint8_t*)xk_blob;sh.xk_off=xk_off;sh.xk_len=xk_len;sh.keyset_count=keyset_count;
    sh.main_name=main_name;sh.main_len=main_len;sh.max_main=max_main;sh.chunk_size=chunk_size;
    sh.found_fb=-1;sh.found_variant=-1;sh.found_lane=-1;sh.found_keyset=-1;sh.found_input=-1;
    /* Initialize runtime dispatch before threads race on the one-time state. */
    (void)iapt_fast_aes128_available();
    pthread_t tids[32];iapt_native_parallel_job jobs[32];int made=0;
    for(int i=0;i<lane_count;i++){
        jobs[i].sh=&sh;jobs[i].lane_id=i;jobs[i].start_fb=lane_start[i];jobs[i].stop_fb=lane_stop[i];jobs[i].direction=lane_dir[i];jobs[i].cpu_id=lane_cpu?lane_cpu[i]:-1;
        if(pthread_create(&tids[i],NULL,iapt_native_parallel_worker,&jobs[i])!=0){sh.stop=1;break;}made++;
    }
    for(int i=0;i<made;i++)pthread_join(tids[i],NULL);
    if(made!=lane_count)return -2;
    if(sh.found_fb>=0){*found_fb=sh.found_fb;if(found_variant)*found_variant=sh.found_variant;
        if(found_lane)*found_lane=sh.found_lane;if(found_keyset)*found_keyset=sh.found_keyset;if(found_input)*found_input=sh.found_input;return 1;}
    return 0;
}

int iapp_broad_hidden_list_scan_mian(const void *ct_ptr, size_t ct_len,
        const void *hidden_blob, int hidden_count, int hidden_len,
        const char *pkg, int pkg_len, const char *vn, int vn_len,
        const char *vc, int vc_len, const char *label, int label_len,
        const char *fb, int fb_len, const void *sig_ptr, int sig_len, const void *jg_ptr, int jg_len,
        const void *post_ptr, int post_len, const void *xk_ptr, int xk_len,
        int start_index, int stop_index, int direction,
        const char *main_name, int main_len, size_t max_main, int *found_index, int *found_alg) {
    if (!ct_ptr || !hidden_blob || hidden_count <= 0 || hidden_len <= 0 || !post_ptr || !xk_ptr || !main_name || !found_index) return -1;
    if (start_index < 0) start_index = 0;
    if (stop_index >= hidden_count) stop_index = hidden_count - 1;
    if (direction == 0) direction = (start_index <= stop_index) ? 1 : -1;
    int idx = start_index;
    const uint8_t *blob = (const uint8_t*)hidden_blob;
    while ((direction > 0 && idx <= stop_index) || (direction < 0 && idx >= stop_index)) {
        const uint8_t *hidden = blob + ((size_t)idx * (size_t)hidden_len);
        int alg = 0;
        if (broad_try_one(ct_ptr, ct_len, hidden, hidden_len, pkg, pkg_len, vn, vn_len, vc, vc_len, label, label_len, fb, fb_len, sig_ptr, sig_len, jg_ptr, jg_len, post_ptr, post_len, xk_ptr, xk_len, main_name, main_len, max_main, &alg)) { *found_index = idx; if(found_alg)*found_alg=alg; return 1; }
        idx += direction;
    }
    return 0;
}


/* v127: fused two-dimensional sokey(hidden) + dexkey scanner.
 * Python builds a priority-ordered list of (hidden,tile) jobs once. Native
 * pthread workers dynamically fetch jobs; no Python process, Queue, or per-
 * sokey ctypes call is involved. input_kind=1 means use the current hidden as
 * the idbfj input, input_kind=0 means use the packed constant input. */
typedef struct {
    const void *ct_ptr; size_t ct_len;
    const uint8_t *hidden_blob; int hidden_count, hidden_len;
    const char *pkg; int pkg_len; const char *vn; int vn_len;
    const char *vc; int vc_len; const char *label; int label_len;
    const uint8_t *input_blob; const int *input_off, *input_len, *input_kind; int input_count;
    const void *sig_ptr; int sig_len;
    const uint8_t *post_blob; const int *post_off, *post_len;
    const uint8_t *xk_blob; const int *xk_off, *xk_len; int keyset_count;
    const int *tile_start, *tile_stop, *tile_dir; int tile_count;
    const int *job_hidden, *job_tile; int job_count;
    const int *row_offsets, *row_tiles; int row_count;
    int row_job_prefix[1025];
    const int *diag_tile_order, *diag_prefix; int diag_count;
    const char *main_name; int main_len; size_t max_main;
    volatile int next_job, stop;
    int found_hidden, found_fb, found_variant, found_keyset, found_input, found_tile;
} iapt_joint_shared;

typedef struct { iapt_joint_shared *s; int cpu_id; } iapt_joint_worker_job;

static void *iapt_joint_worker(void *opaque) {
    iapt_joint_worker_job *wj=(iapt_joint_worker_job*)opaque;
    iapt_joint_shared *s=wj->s;
#if defined(__linux__) || defined(__ANDROID__)
    if(wj->cpu_id>=0){cpu_set_t cs;CPU_ZERO(&cs);CPU_SET(wj->cpu_id,&cs);(void)pthread_setaffinity_np(pthread_self(),sizeof(cs),&cs);}
#endif
    while(!s->stop) {
        int ji=__sync_fetch_and_add(&s->next_job,1);
        if(ji>=s->job_count) break;
        int hi=s->job_hidden[ji], ti=s->job_tile[ji];
        if(hi<0||hi>=s->hidden_count||ti<0||ti>=s->tile_count) continue;
        const uint8_t *hidden=s->hidden_blob+(size_t)hi*(size_t)s->hidden_len;
        int a=s->tile_start[ti], b=s->tile_stop[ti], d=s->tile_dir[ti];
        if(!d)d=(a<=b)?1:-1;
        for(int k=0;k<s->keyset_count&&!s->stop;k++) {
            const uint8_t *post=s->post_blob+s->post_off[k];
            const uint8_t *xk=s->xk_blob+s->xk_off[k];
            for(int q=0;q<s->input_count&&!s->stop;q++) {
                const uint8_t *inp;
                int ilen;
                if(s->input_kind[q]) { inp=hidden; ilen=s->hidden_len; }
                else { inp=s->input_blob+s->input_off[q]; ilen=s->input_len[q]; }
                int hit=0,variant=-1;
                int r=iapp_idbfj_dexkey_scan_mian(
                    s->ct_ptr,s->ct_len,hidden,s->hidden_len,
                    s->pkg,s->pkg_len,s->vn,s->vn_len,s->vc,s->vc_len,s->label,s->label_len,
                    inp,ilen,s->sig_ptr,s->sig_len,a,b,d,
                    post,s->post_len[k],xk,s->xk_len[k],
                    s->main_name,s->main_len,s->max_main,&hit,&variant);
                if(r==1) {
                    if(__sync_bool_compare_and_swap(&s->stop,0,1)) {
                        s->found_hidden=hi;s->found_fb=hit;s->found_variant=variant;
                        s->found_keyset=k;s->found_input=q;s->found_tile=ti;
                    }
                    return NULL;
                }
            }
        }
    }
    return NULL;
}



/* v138: diagonal 2D scheduler.  Job priority is hidden_rank + dex_tile_rank.
 * This prevents a large sokey list from forcing every hidden through one dex
 * depth before a high-priority hidden can advance to its next nearby tile. */
static void *iapt_joint_diagonal_worker(void *opaque) {
    iapt_joint_worker_job *wj=(iapt_joint_worker_job*)opaque;
    iapt_joint_shared *s=wj->s;
#if defined(__linux__) || defined(__ANDROID__)
    if(wj->cpu_id>=0){cpu_set_t cs;CPU_ZERO(&cs);CPU_SET(wj->cpu_id,&cs);(void)pthread_setaffinity_np(pthread_self(),sizeof(cs),&cs);}
#endif
    while(!s->stop) {
        int ji=__sync_fetch_and_add(&s->next_job,1);
        if(ji>=s->job_count)break;
        int lo=0,hi=s->diag_count;
        while(lo+1<hi){int mid=(lo+hi)>>1;if(s->diag_prefix[mid]<=ji)lo=mid;else hi=mid;}
        int d=lo;
        if(d<0||d>=s->diag_count)continue;
        int local=ji-s->diag_prefix[d];
        int hmin=d-(s->tile_count-1);if(hmin<0)hmin=0;
        int hmax=d;if(hmax>=s->hidden_count)hmax=s->hidden_count-1;
        int hidx=hmin+local;
        if(hidx< hmin||hidx>hmax)continue;
        int trank=d-hidx;
        if(trank<0||trank>=s->tile_count)continue;
        int ti=s->diag_tile_order[trank];
        if(ti<0||ti>=s->tile_count)continue;
        const uint8_t *hidden=s->hidden_blob+(size_t)hidx*(size_t)s->hidden_len;
        int a=s->tile_start[ti],b=s->tile_stop[ti],dd=s->tile_dir[ti];
        if(!dd)dd=(a<=b)?1:-1;
        for(int k=0;k<s->keyset_count&&!s->stop;k++){
            const uint8_t *post=s->post_blob+s->post_off[k];
            const uint8_t *xk=s->xk_blob+s->xk_off[k];
            for(int q=0;q<s->input_count&&!s->stop;q++){
                const uint8_t *inp;int ilen;
                if(s->input_kind[q]){inp=hidden;ilen=s->hidden_len;}
                else{inp=s->input_blob+s->input_off[q];ilen=s->input_len[q];}
                int hit=0,variant=-1;
                int rr=iapp_idbfj_dexkey_scan_mian(
                    s->ct_ptr,s->ct_len,hidden,s->hidden_len,
                    s->pkg,s->pkg_len,s->vn,s->vn_len,s->vc,s->vc_len,s->label,s->label_len,
                    inp,ilen,s->sig_ptr,s->sig_len,a,b,dd,
                    post,s->post_len[k],xk,s->xk_len[k],
                    s->main_name,s->main_len,s->max_main,&hit,&variant);
                if(rr==1){
                    if(__sync_bool_compare_and_swap(&s->stop,0,1)){
                        s->found_hidden=hidx;s->found_fb=hit;s->found_variant=variant;
                        s->found_keyset=k;s->found_input=q;s->found_tile=ti;
                    }
                    return NULL;
                }
            }
        }
    }
    return NULL;
}

int iapp_joint_sokey_dexkey_scan_mian_parallel_diagonal(
        const void *ct_ptr,size_t ct_len,
        const void *hidden_blob,int hidden_count,int hidden_len,
        const char *pkg,int pkg_len,const char *vn,int vn_len,const char *vc,int vc_len,
        const char *label,int label_len,
        const void *input_blob,const int *input_off,const int *input_len,const int *input_kind,int input_count,
        const void *sig_ptr,int sig_len,
        const int *tile_start,const int *tile_stop,const int *tile_dir,const int *tile_order,int tile_count,
        const int *thread_cpu,int thread_count,
        const void *post_blob,const int *post_off,const int *post_len,
        const void *xk_blob,const int *xk_off,const int *xk_len,int keyset_count,
        const char *main_name,int main_len,size_t max_main,
        int *found_hidden,int *found_fb,int *found_variant,int *found_keyset,int *found_input,int *found_tile){
    if(!ct_ptr||!hidden_blob||hidden_count<=0||hidden_len<=0||
       !input_off||!input_len||!input_kind||input_count<=0||
       !tile_start||!tile_stop||!tile_dir||!tile_order||tile_count<=0||
       !post_blob||!post_off||!post_len||!xk_blob||!xk_off||!xk_len||keyset_count<=0||
       !main_name||!found_hidden||!found_fb)return -1;
    if(thread_count<1)thread_count=1;if(thread_count>32)thread_count=32;
    int diag_count=hidden_count+tile_count-1;
    int *prefix=(int*)malloc((size_t)(diag_count+1)*sizeof(int));
    if(!prefix)return -2;
    prefix[0]=0;
    for(int d=0;d<diag_count;d++){
        int hmin=d-(tile_count-1);if(hmin<0)hmin=0;
        int hmax=d;if(hmax>=hidden_count)hmax=hidden_count-1;
        int cnt=hmax>=hmin?(hmax-hmin+1):0;
        long long nx=(long long)prefix[d]+cnt;
        if(nx>2147483647LL){free(prefix);return -4;}
        prefix[d+1]=(int)nx;
    }
    iapt_joint_shared s;memset(&s,0,sizeof(s));
    s.ct_ptr=ct_ptr;s.ct_len=ct_len;s.hidden_blob=(const uint8_t*)hidden_blob;
    s.hidden_count=hidden_count;s.hidden_len=hidden_len;s.pkg=pkg;s.pkg_len=pkg_len;
    s.vn=vn;s.vn_len=vn_len;s.vc=vc;s.vc_len=vc_len;s.label=label;s.label_len=label_len;
    s.input_blob=(const uint8_t*)input_blob;s.input_off=input_off;s.input_len=input_len;s.input_kind=input_kind;s.input_count=input_count;
    s.sig_ptr=sig_ptr;s.sig_len=sig_len;s.tile_start=tile_start;s.tile_stop=tile_stop;s.tile_dir=tile_dir;s.tile_count=tile_count;
    s.diag_tile_order=tile_order;s.diag_prefix=prefix;s.diag_count=diag_count;
    s.post_blob=(const uint8_t*)post_blob;s.post_off=post_off;s.post_len=post_len;
    s.xk_blob=(const uint8_t*)xk_blob;s.xk_off=xk_off;s.xk_len=xk_len;s.keyset_count=keyset_count;
    s.main_name=main_name;s.main_len=main_len;s.max_main=max_main;
    s.job_count=prefix[diag_count];
    s.found_hidden=-1;s.found_fb=-1;s.found_variant=-1;s.found_keyset=-1;s.found_input=-1;s.found_tile=-1;
    (void)iapt_fast_aes128_available();
    pthread_t tids[32];iapt_joint_worker_job jobs[32];int made=0;
    for(int i=0;i<thread_count;i++){
        jobs[i].s=&s;jobs[i].cpu_id=thread_cpu?thread_cpu[i]:-1;
        if(pthread_create(&tids[i],NULL,iapt_joint_diagonal_worker,&jobs[i])!=0){s.stop=1;break;}made++;
    }
    for(int i=0;i<made;i++)pthread_join(tids[i],NULL);
    free(prefix);
    if(made!=thread_count)return -3;
    if(s.found_fb>=0){*found_hidden=s.found_hidden;*found_fb=s.found_fb;
        if(found_variant)*found_variant=s.found_variant;if(found_keyset)*found_keyset=s.found_keyset;
        if(found_input)*found_input=s.found_input;if(found_tile)*found_tile=s.found_tile;return 1;}
    return 0;
}

/* v137: lazy joint scheduler.  Python passes only depth-row tile descriptors;
 * workers derive (hidden,tile) from a compact integer job index.  This removes
 * two huge job arrays (tens of millions of Python ints for 180k sokeys). */
static void *iapt_joint_lazy_worker(void *opaque) {
    iapt_joint_worker_job *wj=(iapt_joint_worker_job*)opaque;
    iapt_joint_shared *s=wj->s;
#if defined(__linux__) || defined(__ANDROID__)
    if(wj->cpu_id>=0){cpu_set_t cs;CPU_ZERO(&cs);CPU_SET(wj->cpu_id,&cs);(void)pthread_setaffinity_np(pthread_self(),sizeof(cs),&cs);}
#endif
    while(!s->stop) {
        int ji=__sync_fetch_and_add(&s->next_job,1);
        if(ji>=s->job_count) break;
        int lo=0,hirow=s->row_count;
        while(lo+1<hirow){int mid=(lo+hirow)>>1;if(s->row_job_prefix[mid]<=ji)lo=mid;else hirow=mid;}
        int row=lo;
        if(row<0||row>=s->row_count)continue;
        int r0=s->row_offsets[row],r1=s->row_offsets[row+1],rlen=r1-r0;
        if(rlen<=0)continue;
        int local=ji-s->row_job_prefix[row];
        int hidx=local/rlen;
        int slot=local-hidx*rlen;
        if(hidx<0||hidx>=s->hidden_count||slot<0||slot>=rlen)continue;
        int ti=s->row_tiles[r0+slot];
        if(ti<0||ti>=s->tile_count)continue;
        const uint8_t *hidden=s->hidden_blob+(size_t)hidx*(size_t)s->hidden_len;
        int a=s->tile_start[ti], b=s->tile_stop[ti], d=s->tile_dir[ti];
        if(!d)d=(a<=b)?1:-1;
        for(int k=0;k<s->keyset_count&&!s->stop;k++) {
            const uint8_t *post=s->post_blob+s->post_off[k];
            const uint8_t *xk=s->xk_blob+s->xk_off[k];
            for(int q=0;q<s->input_count&&!s->stop;q++) {
                const uint8_t *inp; int ilen;
                if(s->input_kind[q]) { inp=hidden; ilen=s->hidden_len; }
                else { inp=s->input_blob+s->input_off[q]; ilen=s->input_len[q]; }
                int hit=0,variant=-1;
                int rr=iapp_idbfj_dexkey_scan_mian(
                    s->ct_ptr,s->ct_len,hidden,s->hidden_len,
                    s->pkg,s->pkg_len,s->vn,s->vn_len,s->vc,s->vc_len,s->label,s->label_len,
                    inp,ilen,s->sig_ptr,s->sig_len,a,b,d,
                    post,s->post_len[k],xk,s->xk_len[k],
                    s->main_name,s->main_len,s->max_main,&hit,&variant);
                if(rr==1) {
                    if(__sync_bool_compare_and_swap(&s->stop,0,1)) {
                        s->found_hidden=hidx;s->found_fb=hit;s->found_variant=variant;
                        s->found_keyset=k;s->found_input=q;s->found_tile=ti;
                    }
                    return NULL;
                }
            }
        }
    }
    return NULL;
}

int iapp_joint_sokey_dexkey_scan_mian_parallel_lazy(
        const void *ct_ptr,size_t ct_len,
        const void *hidden_blob,int hidden_count,int hidden_len,
        const char *pkg,int pkg_len,const char *vn,int vn_len,const char *vc,int vc_len,
        const char *label,int label_len,
        const void *input_blob,const int *input_off,const int *input_len,const int *input_kind,int input_count,
        const void *sig_ptr,int sig_len,
        const int *tile_start,const int *tile_stop,const int *tile_dir,int tile_count,
        const int *row_offsets,const int *row_tiles,int row_count,
        const int *thread_cpu,int thread_count,
        const void *post_blob,const int *post_off,const int *post_len,
        const void *xk_blob,const int *xk_off,const int *xk_len,int keyset_count,
        const char *main_name,int main_len,size_t max_main,
        int *found_hidden,int *found_fb,int *found_variant,int *found_keyset,int *found_input,int *found_tile) {
    if(!ct_ptr||!hidden_blob||hidden_count<=0||hidden_len<=0||
       !input_off||!input_len||!input_kind||input_count<=0||
       !tile_start||!tile_stop||!tile_dir||tile_count<=0||
       !row_offsets||!row_tiles||row_count<=0||row_count>1024||
       !post_blob||!post_off||!post_len||!xk_blob||!xk_off||!xk_len||keyset_count<=0||
       !main_name||!found_hidden||!found_fb)return -1;
    if(thread_count<1)thread_count=1;if(thread_count>32)thread_count=32;
    iapt_joint_shared s;memset(&s,0,sizeof(s));
    s.ct_ptr=ct_ptr;s.ct_len=ct_len;s.hidden_blob=(const uint8_t*)hidden_blob;
    s.hidden_count=hidden_count;s.hidden_len=hidden_len;s.pkg=pkg;s.pkg_len=pkg_len;
    s.vn=vn;s.vn_len=vn_len;s.vc=vc;s.vc_len=vc_len;s.label=label;s.label_len=label_len;
    s.input_blob=(const uint8_t*)input_blob;s.input_off=input_off;s.input_len=input_len;s.input_kind=input_kind;s.input_count=input_count;
    s.sig_ptr=sig_ptr;s.sig_len=sig_len;s.tile_start=tile_start;s.tile_stop=tile_stop;s.tile_dir=tile_dir;s.tile_count=tile_count;
    s.row_offsets=row_offsets;s.row_tiles=row_tiles;s.row_count=row_count;
    s.post_blob=(const uint8_t*)post_blob;s.post_off=post_off;s.post_len=post_len;
    s.xk_blob=(const uint8_t*)xk_blob;s.xk_off=xk_off;s.xk_len=xk_len;s.keyset_count=keyset_count;
    s.main_name=main_name;s.main_len=main_len;s.max_main=max_main;
    s.found_hidden=-1;s.found_fb=-1;s.found_variant=-1;s.found_keyset=-1;s.found_input=-1;s.found_tile=-1;
    s.row_job_prefix[0]=0;
    for(int r=0;r<row_count;r++){
        int a=row_offsets[r],b=row_offsets[r+1];
        if(a<0||b<a||b>tile_count)return -3;
        long long next=(long long)s.row_job_prefix[r]+(long long)hidden_count*(long long)(b-a);
        if(next>2147483647LL)return -4;
        s.row_job_prefix[r+1]=(int)next;
    }
    s.job_count=s.row_job_prefix[row_count];
    if(s.job_count<=0)return -5;
    (void)iapt_fast_aes128_available();
    pthread_t tids[32];iapt_joint_worker_job jobs[32];int made=0;
    for(int i=0;i<thread_count;i++){
        jobs[i].s=&s;jobs[i].cpu_id=thread_cpu?thread_cpu[i]:-1;
        if(pthread_create(&tids[i],NULL,iapt_joint_lazy_worker,&jobs[i])!=0){s.stop=1;break;}made++;
    }
    for(int i=0;i<made;i++)pthread_join(tids[i],NULL);
    if(made!=thread_count)return -2;
    if(s.found_fb>=0){*found_hidden=s.found_hidden;*found_fb=s.found_fb;
        if(found_variant)*found_variant=s.found_variant;if(found_keyset)*found_keyset=s.found_keyset;
        if(found_input)*found_input=s.found_input;if(found_tile)*found_tile=s.found_tile;return 1;}
    return 0;
}

int iapp_joint_sokey_dexkey_scan_mian_parallel(
        const void *ct_ptr,size_t ct_len,
        const void *hidden_blob,int hidden_count,int hidden_len,
        const char *pkg,int pkg_len,const char *vn,int vn_len,const char *vc,int vc_len,
        const char *label,int label_len,
        const void *input_blob,const int *input_off,const int *input_len,const int *input_kind,int input_count,
        const void *sig_ptr,int sig_len,
        const int *tile_start,const int *tile_stop,const int *tile_dir,int tile_count,
        const int *job_hidden,const int *job_tile,int job_count,
        const int *thread_cpu,int thread_count,
        const void *post_blob,const int *post_off,const int *post_len,
        const void *xk_blob,const int *xk_off,const int *xk_len,int keyset_count,
        const char *main_name,int main_len,size_t max_main,
        int *found_hidden,int *found_fb,int *found_variant,int *found_keyset,int *found_input,int *found_tile) {
    if(!ct_ptr||!hidden_blob||hidden_count<=0||hidden_len<=0||
       !input_off||!input_len||!input_kind||input_count<=0||
       !tile_start||!tile_stop||!tile_dir||tile_count<=0||
       !job_hidden||!job_tile||job_count<=0||
       !post_blob||!post_off||!post_len||!xk_blob||!xk_off||!xk_len||keyset_count<=0||
       !main_name||!found_hidden||!found_fb)return -1;
    if(thread_count<1)thread_count=1;if(thread_count>32)thread_count=32;
    iapt_joint_shared s;memset(&s,0,sizeof(s));
    s.ct_ptr=ct_ptr;s.ct_len=ct_len;s.hidden_blob=(const uint8_t*)hidden_blob;
    s.hidden_count=hidden_count;s.hidden_len=hidden_len;s.pkg=pkg;s.pkg_len=pkg_len;
    s.vn=vn;s.vn_len=vn_len;s.vc=vc;s.vc_len=vc_len;s.label=label;s.label_len=label_len;
    s.input_blob=(const uint8_t*)input_blob;s.input_off=input_off;s.input_len=input_len;s.input_kind=input_kind;s.input_count=input_count;
    s.sig_ptr=sig_ptr;s.sig_len=sig_len;s.tile_start=tile_start;s.tile_stop=tile_stop;s.tile_dir=tile_dir;s.tile_count=tile_count;
    s.job_hidden=job_hidden;s.job_tile=job_tile;s.job_count=job_count;
    s.post_blob=(const uint8_t*)post_blob;s.post_off=post_off;s.post_len=post_len;
    s.xk_blob=(const uint8_t*)xk_blob;s.xk_off=xk_off;s.xk_len=xk_len;s.keyset_count=keyset_count;
    s.main_name=main_name;s.main_len=main_len;s.max_main=max_main;
    s.found_hidden=-1;s.found_fb=-1;s.found_variant=-1;s.found_keyset=-1;s.found_input=-1;s.found_tile=-1;
    (void)iapt_fast_aes128_available();
    pthread_t tids[32];iapt_joint_worker_job jobs[32];int made=0;
    for(int i=0;i<thread_count;i++){
        jobs[i].s=&s;jobs[i].cpu_id=thread_cpu?thread_cpu[i]:-1;
        if(pthread_create(&tids[i],NULL,iapt_joint_worker,&jobs[i])!=0){s.stop=1;break;}made++;
    }
    for(int i=0;i<made;i++)pthread_join(tids[i],NULL);
    if(made!=thread_count)return -2;
    if(s.found_fb>=0){*found_hidden=s.found_hidden;*found_fb=s.found_fb;
        if(found_variant)*found_variant=s.found_variant;if(found_keyset)*found_keyset=s.found_keyset;
        if(found_input)*found_input=s.found_input;if(found_tile)*found_tile=s.found_tile;return 1;}
    return 0;
}
