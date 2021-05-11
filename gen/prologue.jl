const UINT64_MAX = typemax(UInt64)
const SIZE_MAX = typemax(UInt32)
const crypto_pwhash_argon2i_MEMLIMIT_MAX = ( ( SIZE_MAX >= 4398046510080 ) ? 4398046510080 : ( SIZE_MAX >= Cuint(2147483648) ) ? Cuint(2147483648) : Cuint(32768) )
const crypto_pwhash_argon2id_MEMLIMIT_MAX = ( ( SIZE_MAX >= 4398046510080 ) ? 4398046510080 : ( SIZE_MAX >= Cuint(2147483648) ) ? Cuint(2147483648) : Cuint(32768) )
