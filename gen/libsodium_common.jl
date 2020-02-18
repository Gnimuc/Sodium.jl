# Automatically generated using Clang.jl


const crypto_aead_aes256gcm_KEYBYTES = UInt32(32)
const crypto_aead_aes256gcm_NSECBYTES = UInt32(0)
const crypto_aead_aes256gcm_NPUBBYTES = UInt32(12)
const crypto_aead_aes256gcm_ABYTES = UInt32(16)

# Skipping MacroDefinition: crypto_aead_aes256gcm_MESSAGEBYTES_MAX SODIUM_MIN ( SODIUM_SIZE_MAX - crypto_aead_aes256gcm_ABYTES , ( 16ULL * ( ( 1ULL << 32 ) - 2ULL ) ) )

const crypto_aead_aes256gcm_state = crypto_aead_aes256gcm_state_
const crypto_aead_chacha20poly1305_ietf_KEYBYTES = UInt32(32)
const crypto_aead_chacha20poly1305_ietf_NSECBYTES = UInt32(0)
const crypto_aead_chacha20poly1305_ietf_NPUBBYTES = UInt32(12)
const crypto_aead_chacha20poly1305_ietf_ABYTES = UInt32(16)

# Skipping MacroDefinition: crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX SODIUM_MIN ( SODIUM_SIZE_MAX - crypto_aead_chacha20poly1305_ietf_ABYTES , ( 64ULL * ( ( 1ULL << 32 ) - 1ULL ) ) )

const crypto_aead_chacha20poly1305_KEYBYTES = UInt32(32)
const crypto_aead_chacha20poly1305_NSECBYTES = UInt32(0)
const crypto_aead_chacha20poly1305_NPUBBYTES = UInt32(8)
const crypto_aead_chacha20poly1305_ABYTES = UInt32(16)
const crypto_aead_chacha20poly1305_MESSAGEBYTES_MAX = SODIUM_SIZE_MAX - crypto_aead_chacha20poly1305_ABYTES
const crypto_aead_chacha20poly1305_IETF_KEYBYTES = crypto_aead_chacha20poly1305_ietf_KEYBYTES
const crypto_aead_chacha20poly1305_IETF_NSECBYTES = crypto_aead_chacha20poly1305_ietf_NSECBYTES
const crypto_aead_chacha20poly1305_IETF_NPUBBYTES = crypto_aead_chacha20poly1305_ietf_NPUBBYTES
const crypto_aead_chacha20poly1305_IETF_ABYTES = crypto_aead_chacha20poly1305_ietf_ABYTES
const crypto_aead_chacha20poly1305_IETF_MESSAGEBYTES_MAX = crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX
const crypto_aead_xchacha20poly1305_ietf_KEYBYTES = UInt32(32)
const crypto_aead_xchacha20poly1305_ietf_NSECBYTES = UInt32(0)
const crypto_aead_xchacha20poly1305_ietf_NPUBBYTES = UInt32(24)
const crypto_aead_xchacha20poly1305_ietf_ABYTES = UInt32(16)
const crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX = SODIUM_SIZE_MAX - crypto_aead_xchacha20poly1305_ietf_ABYTES
const crypto_aead_xchacha20poly1305_IETF_KEYBYTES = crypto_aead_xchacha20poly1305_ietf_KEYBYTES
const crypto_aead_xchacha20poly1305_IETF_NSECBYTES = crypto_aead_xchacha20poly1305_ietf_NSECBYTES
const crypto_aead_xchacha20poly1305_IETF_NPUBBYTES = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
const crypto_aead_xchacha20poly1305_IETF_ABYTES = crypto_aead_xchacha20poly1305_ietf_ABYTES
const crypto_aead_xchacha20poly1305_IETF_MESSAGEBYTES_MAX = crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX
const crypto_auth_hmacsha512256_BYTES = UInt32(32)
const crypto_auth_BYTES = crypto_auth_hmacsha512256_BYTES
const crypto_auth_hmacsha512256_KEYBYTES = UInt32(32)
const crypto_auth_KEYBYTES = crypto_auth_hmacsha512256_KEYBYTES
const crypto_auth_PRIMITIVE = "hmacsha512256"
const crypto_auth_hmacsha256_BYTES = UInt32(32)
const crypto_auth_hmacsha256_KEYBYTES = UInt32(32)

struct crypto_hash_sha256_state
    state::NTuple{8, UInt32}
    count::UInt64
    buf::NTuple{64, UInt8}
end

struct crypto_auth_hmacsha256_state
    ictx::crypto_hash_sha256_state
    octx::crypto_hash_sha256_state
end

const crypto_auth_hmacsha512_BYTES = UInt32(64)
const crypto_auth_hmacsha512_KEYBYTES = UInt32(32)

struct crypto_hash_sha512_state
    state::NTuple{8, UInt64}
    count::NTuple{2, UInt64}
    buf::NTuple{128, UInt8}
end

struct crypto_auth_hmacsha512_state
    ictx::crypto_hash_sha512_state
    octx::crypto_hash_sha512_state
end

const crypto_auth_hmacsha512256_state = crypto_auth_hmacsha512_state
const crypto_box_curve25519xsalsa20poly1305_SEEDBYTES = UInt32(32)
const crypto_box_SEEDBYTES = crypto_box_curve25519xsalsa20poly1305_SEEDBYTES
const crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES = UInt32(32)
const crypto_box_PUBLICKEYBYTES = crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES
const crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES = UInt32(32)
const crypto_box_SECRETKEYBYTES = crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES
const crypto_box_curve25519xsalsa20poly1305_NONCEBYTES = UInt32(24)
const crypto_box_NONCEBYTES = crypto_box_curve25519xsalsa20poly1305_NONCEBYTES
const crypto_box_curve25519xsalsa20poly1305_MACBYTES = UInt32(16)
const crypto_box_MACBYTES = crypto_box_curve25519xsalsa20poly1305_MACBYTES
const crypto_stream_xsalsa20_MESSAGEBYTES_MAX = SODIUM_SIZE_MAX
const crypto_box_curve25519xsalsa20poly1305_MESSAGEBYTES_MAX = crypto_stream_xsalsa20_MESSAGEBYTES_MAX - crypto_box_curve25519xsalsa20poly1305_MACBYTES
const crypto_box_MESSAGEBYTES_MAX = crypto_box_curve25519xsalsa20poly1305_MESSAGEBYTES_MAX
const crypto_box_PRIMITIVE = "curve25519xsalsa20poly1305"
const crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES = UInt32(32)
const crypto_box_BEFORENMBYTES = crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES
const crypto_box_SEALBYTES = crypto_box_PUBLICKEYBYTES + crypto_box_MACBYTES
const crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES = UInt32(16)
const crypto_box_curve25519xsalsa20poly1305_ZEROBYTES = crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES + crypto_box_curve25519xsalsa20poly1305_MACBYTES
const crypto_box_ZEROBYTES = crypto_box_curve25519xsalsa20poly1305_ZEROBYTES
const crypto_box_BOXZEROBYTES = crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES
const crypto_box_curve25519xchacha20poly1305_SEEDBYTES = UInt32(32)
const crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES = UInt32(32)
const crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES = UInt32(32)
const crypto_box_curve25519xchacha20poly1305_BEFORENMBYTES = UInt32(32)
const crypto_box_curve25519xchacha20poly1305_NONCEBYTES = UInt32(24)
const crypto_box_curve25519xchacha20poly1305_MACBYTES = UInt32(16)
const crypto_stream_xchacha20_MESSAGEBYTES_MAX = SODIUM_SIZE_MAX
const crypto_box_curve25519xchacha20poly1305_MESSAGEBYTES_MAX = crypto_stream_xchacha20_MESSAGEBYTES_MAX - crypto_box_curve25519xchacha20poly1305_MACBYTES
const crypto_box_curve25519xchacha20poly1305_SEALBYTES = crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES + crypto_box_curve25519xchacha20poly1305_MACBYTES
const crypto_core_ed25519_BYTES = 32
const crypto_core_ed25519_UNIFORMBYTES = 32
const crypto_core_ed25519_HASHBYTES = 64
const crypto_core_ed25519_SCALARBYTES = 32
const crypto_core_ed25519_NONREDUCEDSCALARBYTES = 64
const crypto_core_hchacha20_OUTPUTBYTES = UInt32(32)
const crypto_core_hchacha20_INPUTBYTES = UInt32(16)
const crypto_core_hchacha20_KEYBYTES = UInt32(32)
const crypto_core_hchacha20_CONSTBYTES = UInt32(16)
const crypto_core_hsalsa20_OUTPUTBYTES = UInt32(32)
const crypto_core_hsalsa20_INPUTBYTES = UInt32(16)
const crypto_core_hsalsa20_KEYBYTES = UInt32(32)
const crypto_core_hsalsa20_CONSTBYTES = UInt32(16)
const crypto_core_ristretto255_BYTES = 32
const crypto_core_ristretto255_HASHBYTES = 64
const crypto_core_ristretto255_SCALARBYTES = 32
const crypto_core_ristretto255_NONREDUCEDSCALARBYTES = 64
const crypto_core_salsa20_OUTPUTBYTES = UInt32(64)
const crypto_core_salsa20_INPUTBYTES = UInt32(16)
const crypto_core_salsa20_KEYBYTES = UInt32(32)
const crypto_core_salsa20_CONSTBYTES = UInt32(16)
const crypto_core_salsa2012_OUTPUTBYTES = UInt32(64)
const crypto_core_salsa2012_INPUTBYTES = UInt32(16)
const crypto_core_salsa2012_KEYBYTES = UInt32(32)
const crypto_core_salsa2012_CONSTBYTES = UInt32(16)
const crypto_core_salsa208_OUTPUTBYTES = UInt32(64)
const crypto_core_salsa208_INPUTBYTES = UInt32(16)
const crypto_core_salsa208_KEYBYTES = UInt32(32)
const crypto_core_salsa208_CONSTBYTES = UInt32(16)
const crypto_generichash_blake2b_BYTES_MIN = UInt32(16)
const crypto_generichash_BYTES_MIN = crypto_generichash_blake2b_BYTES_MIN
const crypto_generichash_blake2b_BYTES_MAX = UInt32(64)
const crypto_generichash_BYTES_MAX = crypto_generichash_blake2b_BYTES_MAX
const crypto_generichash_blake2b_BYTES = UInt32(32)
const crypto_generichash_BYTES = crypto_generichash_blake2b_BYTES
const crypto_generichash_blake2b_KEYBYTES_MIN = UInt32(16)
const crypto_generichash_KEYBYTES_MIN = crypto_generichash_blake2b_KEYBYTES_MIN
const crypto_generichash_blake2b_KEYBYTES_MAX = UInt32(64)
const crypto_generichash_KEYBYTES_MAX = crypto_generichash_blake2b_KEYBYTES_MAX
const crypto_generichash_blake2b_KEYBYTES = UInt32(32)
const crypto_generichash_KEYBYTES = crypto_generichash_blake2b_KEYBYTES
const crypto_generichash_PRIMITIVE = "blake2b"
const crypto_generichash_state = crypto_generichash_blake2b_state
const crypto_generichash_blake2b_SALTBYTES = UInt32(16)
const crypto_generichash_blake2b_PERSONALBYTES = UInt32(16)
const crypto_hash_sha512_BYTES = UInt32(64)
const crypto_hash_BYTES = crypto_hash_sha512_BYTES
const crypto_hash_PRIMITIVE = "sha512"
const crypto_hash_sha256_BYTES = UInt32(32)
const crypto_kdf_blake2b_BYTES_MIN = 16
const crypto_kdf_BYTES_MIN = crypto_kdf_blake2b_BYTES_MIN
const crypto_kdf_blake2b_BYTES_MAX = 64
const crypto_kdf_BYTES_MAX = crypto_kdf_blake2b_BYTES_MAX
const crypto_kdf_blake2b_CONTEXTBYTES = 8
const crypto_kdf_CONTEXTBYTES = crypto_kdf_blake2b_CONTEXTBYTES
const crypto_kdf_blake2b_KEYBYTES = 32
const crypto_kdf_KEYBYTES = crypto_kdf_blake2b_KEYBYTES
const crypto_kdf_PRIMITIVE = "blake2b"
const crypto_kx_PUBLICKEYBYTES = 32
const crypto_kx_SECRETKEYBYTES = 32
const crypto_kx_SEEDBYTES = 32
const crypto_kx_SESSIONKEYBYTES = 32
const crypto_kx_PRIMITIVE = "x25519blake2b"
const crypto_onetimeauth_poly1305_BYTES = UInt32(16)
const crypto_onetimeauth_BYTES = crypto_onetimeauth_poly1305_BYTES
const crypto_onetimeauth_poly1305_KEYBYTES = UInt32(32)
const crypto_onetimeauth_KEYBYTES = crypto_onetimeauth_poly1305_KEYBYTES
const crypto_onetimeauth_PRIMITIVE = "poly1305"
const crypto_onetimeauth_state = crypto_onetimeauth_poly1305_state
const crypto_pwhash_argon2i_ALG_ARGON2I13 = 1
const crypto_pwhash_ALG_ARGON2I13 = crypto_pwhash_argon2i_ALG_ARGON2I13
const crypto_pwhash_argon2id_ALG_ARGON2ID13 = 2
const crypto_pwhash_ALG_ARGON2ID13 = crypto_pwhash_argon2id_ALG_ARGON2ID13
const crypto_pwhash_ALG_DEFAULT = crypto_pwhash_ALG_ARGON2ID13
const crypto_pwhash_argon2id_BYTES_MIN = UInt32(16)
const crypto_pwhash_BYTES_MIN = crypto_pwhash_argon2id_BYTES_MIN
const crypto_pwhash_BYTES_MAX = crypto_pwhash_argon2id_BYTES_MAX
const crypto_pwhash_argon2id_PASSWD_MIN = UInt32(0)
const crypto_pwhash_PASSWD_MIN = crypto_pwhash_argon2id_PASSWD_MIN
const crypto_pwhash_argon2id_PASSWD_MAX = UInt32(4294967295)
const crypto_pwhash_PASSWD_MAX = crypto_pwhash_argon2id_PASSWD_MAX
const crypto_pwhash_argon2id_SALTBYTES = UInt32(16)
const crypto_pwhash_SALTBYTES = crypto_pwhash_argon2id_SALTBYTES
const crypto_pwhash_argon2id_STRBYTES = UInt32(128)
const crypto_pwhash_STRBYTES = crypto_pwhash_argon2id_STRBYTES
const crypto_pwhash_argon2id_STRPREFIX = "\$argon2id\$"
const crypto_pwhash_STRPREFIX = crypto_pwhash_argon2id_STRPREFIX
const crypto_pwhash_argon2id_OPSLIMIT_MIN = UInt32(1)
const crypto_pwhash_OPSLIMIT_MIN = crypto_pwhash_argon2id_OPSLIMIT_MIN
const crypto_pwhash_argon2id_OPSLIMIT_MAX = UInt32(4294967295)
const crypto_pwhash_OPSLIMIT_MAX = crypto_pwhash_argon2id_OPSLIMIT_MAX
const crypto_pwhash_argon2id_MEMLIMIT_MIN = UInt32(8192)
const crypto_pwhash_MEMLIMIT_MIN = crypto_pwhash_argon2id_MEMLIMIT_MIN
const crypto_pwhash_MEMLIMIT_MAX = crypto_pwhash_argon2id_MEMLIMIT_MAX
const crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE = UInt32(2)
const crypto_pwhash_OPSLIMIT_INTERACTIVE = crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE
const crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE = UInt32(67108864)
const crypto_pwhash_MEMLIMIT_INTERACTIVE = crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE
const crypto_pwhash_argon2id_OPSLIMIT_MODERATE = UInt32(3)
const crypto_pwhash_OPSLIMIT_MODERATE = crypto_pwhash_argon2id_OPSLIMIT_MODERATE
const crypto_pwhash_argon2id_MEMLIMIT_MODERATE = UInt32(268435456)
const crypto_pwhash_MEMLIMIT_MODERATE = crypto_pwhash_argon2id_MEMLIMIT_MODERATE
const crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE = UInt32(4)
const crypto_pwhash_OPSLIMIT_SENSITIVE = crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE
const crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE = UInt32(1073741824)
const crypto_pwhash_MEMLIMIT_SENSITIVE = crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE
const crypto_pwhash_PRIMITIVE = "argon2i"
const crypto_pwhash_argon2i_BYTES_MIN = UInt32(16)

# Skipping MacroDefinition: crypto_pwhash_argon2i_BYTES_MAX SODIUM_MIN ( SODIUM_SIZE_MAX , 4294967295U )

const crypto_pwhash_argon2i_PASSWD_MIN = UInt32(0)
const crypto_pwhash_argon2i_PASSWD_MAX = UInt32(4294967295)
const crypto_pwhash_argon2i_SALTBYTES = UInt32(16)
const crypto_pwhash_argon2i_STRBYTES = UInt32(128)
const crypto_pwhash_argon2i_STRPREFIX = "\$argon2i\$"
const crypto_pwhash_argon2i_OPSLIMIT_MIN = UInt32(3)
const crypto_pwhash_argon2i_OPSLIMIT_MAX = UInt32(4294967295)
const crypto_pwhash_argon2i_MEMLIMIT_MIN = UInt32(8192)

# Skipping MacroDefinition: crypto_pwhash_argon2i_MEMLIMIT_MAX ( ( SIZE_MAX >= 4398046510080U ) ? 4398046510080U : ( SIZE_MAX >= 2147483648U ) ? 2147483648U : 32768U )

const crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE = UInt32(4)
const crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE = UInt32(33554432)
const crypto_pwhash_argon2i_OPSLIMIT_MODERATE = UInt32(6)
const crypto_pwhash_argon2i_MEMLIMIT_MODERATE = UInt32(134217728)
const crypto_pwhash_argon2i_OPSLIMIT_SENSITIVE = UInt32(8)
const crypto_pwhash_argon2i_MEMLIMIT_SENSITIVE = UInt32(536870912)

# Skipping MacroDefinition: crypto_pwhash_argon2id_BYTES_MAX SODIUM_MIN ( SODIUM_SIZE_MAX , 4294967295U )
# Skipping MacroDefinition: crypto_pwhash_argon2id_MEMLIMIT_MAX ( ( SIZE_MAX >= 4398046510080U ) ? 4398046510080U : ( SIZE_MAX >= 2147483648U ) ? 2147483648U : 32768U )

const crypto_pwhash_scryptsalsa208sha256_BYTES_MIN = UInt32(16)

# Skipping MacroDefinition: crypto_pwhash_scryptsalsa208sha256_BYTES_MAX SODIUM_MIN ( SODIUM_SIZE_MAX , 0x1fffffffe0ULL )

const crypto_pwhash_scryptsalsa208sha256_PASSWD_MIN = UInt32(0)
const crypto_pwhash_scryptsalsa208sha256_PASSWD_MAX = SODIUM_SIZE_MAX
const crypto_pwhash_scryptsalsa208sha256_SALTBYTES = UInt32(32)
const crypto_pwhash_scryptsalsa208sha256_STRBYTES = UInt32(102)
const crypto_pwhash_scryptsalsa208sha256_STRPREFIX = "\$7\$"
const crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN = UInt32(32768)
const crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX = UInt32(4294967295)
const crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN = UInt32(16777216)

# Skipping MacroDefinition: crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX SODIUM_MIN ( SIZE_MAX , 68719476736ULL )

const crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE = UInt32(524288)
const crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE = UInt32(16777216)
const crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE = UInt32(33554432)
const crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE = UInt32(1073741824)
const crypto_scalarmult_curve25519_BYTES = UInt32(32)
const crypto_scalarmult_BYTES = crypto_scalarmult_curve25519_BYTES
const crypto_scalarmult_curve25519_SCALARBYTES = UInt32(32)
const crypto_scalarmult_SCALARBYTES = crypto_scalarmult_curve25519_SCALARBYTES
const crypto_scalarmult_PRIMITIVE = "curve25519"
const crypto_scalarmult_ed25519_BYTES = UInt32(32)
const crypto_scalarmult_ed25519_SCALARBYTES = UInt32(32)
const crypto_scalarmult_ristretto255_BYTES = UInt32(32)
const crypto_scalarmult_ristretto255_SCALARBYTES = UInt32(32)
const crypto_secretbox_xsalsa20poly1305_KEYBYTES = UInt32(32)
const crypto_secretbox_KEYBYTES = crypto_secretbox_xsalsa20poly1305_KEYBYTES
const crypto_secretbox_xsalsa20poly1305_NONCEBYTES = UInt32(24)
const crypto_secretbox_NONCEBYTES = crypto_secretbox_xsalsa20poly1305_NONCEBYTES
const crypto_secretbox_xsalsa20poly1305_MACBYTES = UInt32(16)
const crypto_secretbox_MACBYTES = crypto_secretbox_xsalsa20poly1305_MACBYTES
const crypto_secretbox_PRIMITIVE = "xsalsa20poly1305"
const crypto_secretbox_xsalsa20poly1305_MESSAGEBYTES_MAX = crypto_stream_xsalsa20_MESSAGEBYTES_MAX - crypto_secretbox_xsalsa20poly1305_MACBYTES
const crypto_secretbox_MESSAGEBYTES_MAX = crypto_secretbox_xsalsa20poly1305_MESSAGEBYTES_MAX
const crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES = UInt32(16)
const crypto_secretbox_xsalsa20poly1305_ZEROBYTES = crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES + crypto_secretbox_xsalsa20poly1305_MACBYTES
const crypto_secretbox_ZEROBYTES = crypto_secretbox_xsalsa20poly1305_ZEROBYTES
const crypto_secretbox_BOXZEROBYTES = crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES
const crypto_secretbox_xchacha20poly1305_KEYBYTES = UInt32(32)
const crypto_secretbox_xchacha20poly1305_NONCEBYTES = UInt32(24)
const crypto_secretbox_xchacha20poly1305_MACBYTES = UInt32(16)
const crypto_secretbox_xchacha20poly1305_MESSAGEBYTES_MAX = crypto_stream_xchacha20_MESSAGEBYTES_MAX - crypto_secretbox_xchacha20poly1305_MACBYTES
const crypto_secretstream_xchacha20poly1305_ABYTES = UInt32(1) + crypto_aead_xchacha20poly1305_ietf_ABYTES
const crypto_secretstream_xchacha20poly1305_HEADERBYTES = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
const crypto_secretstream_xchacha20poly1305_KEYBYTES = crypto_aead_xchacha20poly1305_ietf_KEYBYTES

# Skipping MacroDefinition: crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX SODIUM_MIN ( SODIUM_SIZE_MAX - crypto_secretstream_xchacha20poly1305_ABYTES , ( 64ULL * ( ( 1ULL << 32 ) - 2ULL ) ) )

const crypto_secretstream_xchacha20poly1305_TAG_MESSAGE = 0x00
const crypto_secretstream_xchacha20poly1305_TAG_PUSH = 0x01
const crypto_secretstream_xchacha20poly1305_TAG_REKEY = 0x02
const crypto_secretstream_xchacha20poly1305_TAG_FINAL = crypto_secretstream_xchacha20poly1305_TAG_PUSH | crypto_secretstream_xchacha20poly1305_TAG_REKEY

struct crypto_secretstream_xchacha20poly1305_state
    k::NTuple{32, Cuchar}
    nonce::NTuple{12, Cuchar}
    _pad::NTuple{8, Cuchar}
end

const crypto_shorthash_siphash24_BYTES = UInt32(8)
const crypto_shorthash_BYTES = crypto_shorthash_siphash24_BYTES
const crypto_shorthash_siphash24_KEYBYTES = UInt32(16)
const crypto_shorthash_KEYBYTES = crypto_shorthash_siphash24_KEYBYTES
const crypto_shorthash_PRIMITIVE = "siphash24"
const crypto_shorthash_siphashx24_BYTES = UInt32(16)
const crypto_shorthash_siphashx24_KEYBYTES = UInt32(16)
const crypto_sign_ed25519_BYTES = UInt32(64)
const crypto_sign_BYTES = crypto_sign_ed25519_BYTES
const crypto_sign_ed25519_SEEDBYTES = UInt32(32)
const crypto_sign_SEEDBYTES = crypto_sign_ed25519_SEEDBYTES
const crypto_sign_ed25519_PUBLICKEYBYTES = UInt32(32)
const crypto_sign_PUBLICKEYBYTES = crypto_sign_ed25519_PUBLICKEYBYTES
const crypto_sign_ed25519_SECRETKEYBYTES = UInt32(32) + UInt32(32)
const crypto_sign_SECRETKEYBYTES = crypto_sign_ed25519_SECRETKEYBYTES
const crypto_sign_ed25519_MESSAGEBYTES_MAX = SODIUM_SIZE_MAX - crypto_sign_ed25519_BYTES
const crypto_sign_MESSAGEBYTES_MAX = crypto_sign_ed25519_MESSAGEBYTES_MAX
const crypto_sign_PRIMITIVE = "ed25519"

struct crypto_sign_ed25519ph_state
    hs::crypto_hash_sha512_state
end

const crypto_sign_state = crypto_sign_ed25519ph_state
const crypto_sign_edwards25519sha512batch_BYTES = UInt32(64)
const crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES = UInt32(32)
const crypto_sign_edwards25519sha512batch_SECRETKEYBYTES = UInt32(32) + UInt32(32)
const crypto_sign_edwards25519sha512batch_MESSAGEBYTES_MAX = SODIUM_SIZE_MAX - crypto_sign_edwards25519sha512batch_BYTES
const crypto_stream_xsalsa20_KEYBYTES = UInt32(32)
const crypto_stream_KEYBYTES = crypto_stream_xsalsa20_KEYBYTES
const crypto_stream_xsalsa20_NONCEBYTES = UInt32(24)
const crypto_stream_NONCEBYTES = crypto_stream_xsalsa20_NONCEBYTES
const crypto_stream_MESSAGEBYTES_MAX = crypto_stream_xsalsa20_MESSAGEBYTES_MAX
const crypto_stream_PRIMITIVE = "xsalsa20"
const crypto_stream_chacha20_KEYBYTES = UInt32(32)
const crypto_stream_chacha20_NONCEBYTES = UInt32(8)
const crypto_stream_chacha20_MESSAGEBYTES_MAX = SODIUM_SIZE_MAX
const crypto_stream_chacha20_ietf_KEYBYTES = UInt32(32)
const crypto_stream_chacha20_ietf_NONCEBYTES = UInt32(12)

# Skipping MacroDefinition: crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX SODIUM_MIN ( SODIUM_SIZE_MAX , 64ULL * ( 1ULL << 32 ) )

const crypto_stream_chacha20_IETF_KEYBYTES = crypto_stream_chacha20_ietf_KEYBYTES
const crypto_stream_chacha20_IETF_NONCEBYTES = crypto_stream_chacha20_ietf_NONCEBYTES
const crypto_stream_chacha20_IETF_MESSAGEBYTES_MAX = crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX
const crypto_stream_salsa20_KEYBYTES = UInt32(32)
const crypto_stream_salsa20_NONCEBYTES = UInt32(8)
const crypto_stream_salsa20_MESSAGEBYTES_MAX = SODIUM_SIZE_MAX
const crypto_stream_salsa2012_KEYBYTES = UInt32(32)
const crypto_stream_salsa2012_NONCEBYTES = UInt32(8)
const crypto_stream_salsa2012_MESSAGEBYTES_MAX = SODIUM_SIZE_MAX
const crypto_stream_salsa208_KEYBYTES = UInt32(32)
const crypto_stream_salsa208_NONCEBYTES = UInt32(8)
const crypto_stream_salsa208_MESSAGEBYTES_MAX = SODIUM_SIZE_MAX
const crypto_stream_xchacha20_KEYBYTES = UInt32(32)
const crypto_stream_xchacha20_NONCEBYTES = UInt32(24)
const crypto_verify_16_BYTES = UInt32(16)
const crypto_verify_32_BYTES = UInt32(32)
const crypto_verify_64_BYTES = UInt32(64)

# Skipping MacroDefinition: SODIUM_EXPORT __attribute__ ( ( visibility ( "default" ) ) )

const SODIUM_EXPORT_WEAK = SODIUM_EXPORT

# Skipping MacroDefinition: CRYPTO_ALIGN ( x ) __attribute__ ( ( aligned ( x ) ) )
# Skipping MacroDefinition: SODIUM_MIN ( A , B ) ( ( A ) < ( B ) ? ( A ) : ( B ) )
# Skipping MacroDefinition: SODIUM_SIZE_MAX SODIUM_MIN ( UINT64_MAX , SIZE_MAX )
# Skipping MacroDefinition: randombytes_BYTES_MAX SODIUM_MIN ( SODIUM_SIZE_MAX , 0xffffffffUL )

const randombytes_SEEDBYTES = UInt32(32)

struct randombytes_implementation
    implementation_name::Ptr{Cvoid}
    random::Ptr{Cvoid}
    stir::Ptr{Cvoid}
    uniform::Ptr{Cvoid}
    buf::Ptr{Cvoid}
    close::Ptr{Cvoid}
end

const randombytes_salsa20_implementation = randombytes_internal_implementation

# Skipping MacroDefinition: SODIUM_C99 ( X ) X

const sodium_base64_VARIANT_ORIGINAL = 1
const sodium_base64_VARIANT_ORIGINAL_NO_PADDING = 3
const sodium_base64_VARIANT_URLSAFE = 5
const sodium_base64_VARIANT_URLSAFE_NO_PADDING = 7

# Skipping MacroDefinition: sodium_base64_ENCODED_LEN ( BIN_LEN , VARIANT ) ( ( ( BIN_LEN ) / 3U ) * 4U + ( ( ( ( BIN_LEN ) - ( ( BIN_LEN ) / 3U ) * 3U ) | ( ( ( BIN_LEN ) - ( ( BIN_LEN ) / 3U ) * 3U ) >> 1 ) ) & 1U ) * ( 4U - ( ~ ( ( ( ( VARIANT ) & 2U ) >> 1 ) - 1U ) & ( 3U - ( ( BIN_LEN ) - ( ( BIN_LEN ) / 3U ) * 3U ) ) ) ) + 1U )

const SODIUM_VERSION_STRING = "1.0.18"
const SODIUM_LIBRARY_VERSION_MAJOR = 10
const SODIUM_LIBRARY_VERSION_MINOR = 3
