from intbytes import int2bytes

p = 2**255 - 19
base = 9
bad_public_keys = [0,
                   1,
                   325606250916557431795983626356110631294008115727848805560023387167927233504,
                   39382357235489614581723060781553021112529911719440698176882885853963445705823,
                   p - 1,
                   p,
                   p + 1,
                   p + 325606250916557431795983626356110631294008115727848805560023387167927233504,
                   p + 39382357235489614581723060781553021112529911719440698176882885853963445705823,
                   2*p - 1,
                   2*p,
                   2*p + 1]
p = int2bytes(p, length=32, endian='little')
base = int2bytes(base, length=32, endian='little')
bad_public_keys = map(lambda x: int2bytes(x, length=32, endian='little'),
                      bad_public_keys)
    
del int2bytes
