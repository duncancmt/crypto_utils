#ifndef CURVE25519_DONNA
#define CURVE25519_DONNA

typedef uint8_t u8;
typedef int32_t s32;
typedef int64_t limb;

extern int curve25519_donna(u8 *, const u8 *, const u8 *);
extern void fexpand(limb *, const u8 *);
extern void fmul(limb *, const limb *, const limb *);
extern void fcontract(u8 *, limb *);
extern void crecip(limb *, const limb *);

#endif
