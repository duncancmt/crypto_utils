#ifndef CURVE25519_DONNA
#define CURVE25519_DONNA

typedef uint8_t u8;

extern void mul(u8 *, const u8 *, const u8 *);
extern void expand(u8 *, const u8 *);
extern void contract(u8 *, const u8 *);
extern void recip(u8 *, const u8 *);
extern int curve25519_donna(u8 *, const u8 *, const u8 *);

#endif
