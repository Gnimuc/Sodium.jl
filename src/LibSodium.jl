module LibSodium

using libsodium_jll
export libsodium_jll

const UINT64_MAX = typemax(UInt64)
const SIZE_MAX = typemax(UInt32)
const crypto_pwhash_argon2i_MEMLIMIT_MAX = ( ( SIZE_MAX >= 4398046510080 ) ? 4398046510080 : ( SIZE_MAX >= Cuint(2147483648) ) ? Cuint(2147483648) : Cuint(32768) )
const crypto_pwhash_argon2id_MEMLIMIT_MAX = ( ( SIZE_MAX >= 4398046510080 ) ? 4398046510080 : ( SIZE_MAX >= Cuint(2147483648) ) ? Cuint(2147483648) : Cuint(32768) )


function crypto_sign_edwards25519sha512batch(sm, smlen_p, m, mlen, sk)
    ccall((:crypto_sign_edwards25519sha512batch, libsodium), Cint, (Ptr{Cuchar}, Ptr{Culonglong}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}), sm, smlen_p, m, mlen, sk)
end

function crypto_sign_edwards25519sha512batch_open(m, mlen_p, sm, smlen, pk)
    ccall((:crypto_sign_edwards25519sha512batch_open, libsodium), Cint, (Ptr{Cuchar}, Ptr{Culonglong}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}), m, mlen_p, sm, smlen, pk)
end

function crypto_sign_edwards25519sha512batch_keypair(pk, sk)
    ccall((:crypto_sign_edwards25519sha512batch_keypair, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}), pk, sk)
end

function sodium_version_string()
    ccall((:sodium_version_string, libsodium), Ptr{Cchar}, ())
end

function sodium_library_version_major()
    ccall((:sodium_library_version_major, libsodium), Cint, ())
end

function sodium_library_version_minor()
    ccall((:sodium_library_version_minor, libsodium), Cint, ())
end

function sodium_library_minimal()
    ccall((:sodium_library_minimal, libsodium), Cint, ())
end

function sodium_init()
    ccall((:sodium_init, libsodium), Cint, ())
end

function sodium_set_misuse_handler(handler)
    ccall((:sodium_set_misuse_handler, libsodium), Cint, (Ptr{Cvoid},), handler)
end

function sodium_misuse()
    ccall((:sodium_misuse, libsodium), Cvoid, ())
end

function crypto_aead_aes256gcm_is_available()
    ccall((:crypto_aead_aes256gcm_is_available, libsodium), Cint, ())
end

function crypto_aead_aes256gcm_keybytes()
    ccall((:crypto_aead_aes256gcm_keybytes, libsodium), Csize_t, ())
end

function crypto_aead_aes256gcm_nsecbytes()
    ccall((:crypto_aead_aes256gcm_nsecbytes, libsodium), Csize_t, ())
end

function crypto_aead_aes256gcm_npubbytes()
    ccall((:crypto_aead_aes256gcm_npubbytes, libsodium), Csize_t, ())
end

function crypto_aead_aes256gcm_abytes()
    ccall((:crypto_aead_aes256gcm_abytes, libsodium), Csize_t, ())
end

function crypto_aead_aes256gcm_messagebytes_max()
    ccall((:crypto_aead_aes256gcm_messagebytes_max, libsodium), Csize_t, ())
end

struct crypto_aead_aes256gcm_state_
    data::NTuple{512, UInt8}
end

function Base.getproperty(x::Ptr{crypto_aead_aes256gcm_state_}, f::Symbol)
    f === :opaque && return Ptr{NTuple{512, Cuchar}}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::crypto_aead_aes256gcm_state_, f::Symbol)
    r = Ref{crypto_aead_aes256gcm_state_}(x)
    ptr = Base.unsafe_convert(Ptr{crypto_aead_aes256gcm_state_}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{crypto_aead_aes256gcm_state_}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

const crypto_aead_aes256gcm_state = crypto_aead_aes256gcm_state_

function crypto_aead_aes256gcm_statebytes()
    ccall((:crypto_aead_aes256gcm_statebytes, libsodium), Csize_t, ())
end

function crypto_aead_aes256gcm_encrypt(c, clen_p, m, mlen, ad, adlen, nsec, npub, k)
    ccall((:crypto_aead_aes256gcm_encrypt, libsodium), Cint, (Ptr{Cuchar}, Ptr{Culonglong}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), c, clen_p, m, mlen, ad, adlen, nsec, npub, k)
end

function crypto_aead_aes256gcm_decrypt(m, mlen_p, nsec, c, clen, ad, adlen, npub, k)
    ccall((:crypto_aead_aes256gcm_decrypt, libsodium), Cint, (Ptr{Cuchar}, Ptr{Culonglong}, Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), m, mlen_p, nsec, c, clen, ad, adlen, npub, k)
end

function crypto_aead_aes256gcm_encrypt_detached(c, mac, maclen_p, m, mlen, ad, adlen, nsec, npub, k)
    ccall((:crypto_aead_aes256gcm_encrypt_detached, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Culonglong}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), c, mac, maclen_p, m, mlen, ad, adlen, nsec, npub, k)
end

function crypto_aead_aes256gcm_decrypt_detached(m, nsec, c, clen, mac, ad, adlen, npub, k)
    ccall((:crypto_aead_aes256gcm_decrypt_detached, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), m, nsec, c, clen, mac, ad, adlen, npub, k)
end

function crypto_aead_aes256gcm_beforenm(ctx_, k)
    ccall((:crypto_aead_aes256gcm_beforenm, libsodium), Cint, (Ptr{crypto_aead_aes256gcm_state}, Ptr{Cuchar}), ctx_, k)
end

function crypto_aead_aes256gcm_encrypt_afternm(c, clen_p, m, mlen, ad, adlen, nsec, npub, ctx_)
    ccall((:crypto_aead_aes256gcm_encrypt_afternm, libsodium), Cint, (Ptr{Cuchar}, Ptr{Culonglong}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}, Ptr{crypto_aead_aes256gcm_state}), c, clen_p, m, mlen, ad, adlen, nsec, npub, ctx_)
end

function crypto_aead_aes256gcm_decrypt_afternm(m, mlen_p, nsec, c, clen, ad, adlen, npub, ctx_)
    ccall((:crypto_aead_aes256gcm_decrypt_afternm, libsodium), Cint, (Ptr{Cuchar}, Ptr{Culonglong}, Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{crypto_aead_aes256gcm_state}), m, mlen_p, nsec, c, clen, ad, adlen, npub, ctx_)
end

function crypto_aead_aes256gcm_encrypt_detached_afternm(c, mac, maclen_p, m, mlen, ad, adlen, nsec, npub, ctx_)
    ccall((:crypto_aead_aes256gcm_encrypt_detached_afternm, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Culonglong}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}, Ptr{crypto_aead_aes256gcm_state}), c, mac, maclen_p, m, mlen, ad, adlen, nsec, npub, ctx_)
end

function crypto_aead_aes256gcm_decrypt_detached_afternm(m, nsec, c, clen, mac, ad, adlen, npub, ctx_)
    ccall((:crypto_aead_aes256gcm_decrypt_detached_afternm, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{crypto_aead_aes256gcm_state}), m, nsec, c, clen, mac, ad, adlen, npub, ctx_)
end

function crypto_aead_aes256gcm_keygen(k)
    ccall((:crypto_aead_aes256gcm_keygen, libsodium), Cvoid, (Ptr{Cuchar},), k)
end

function crypto_aead_chacha20poly1305_ietf_keybytes()
    ccall((:crypto_aead_chacha20poly1305_ietf_keybytes, libsodium), Csize_t, ())
end

function crypto_aead_chacha20poly1305_ietf_nsecbytes()
    ccall((:crypto_aead_chacha20poly1305_ietf_nsecbytes, libsodium), Csize_t, ())
end

function crypto_aead_chacha20poly1305_ietf_npubbytes()
    ccall((:crypto_aead_chacha20poly1305_ietf_npubbytes, libsodium), Csize_t, ())
end

function crypto_aead_chacha20poly1305_ietf_abytes()
    ccall((:crypto_aead_chacha20poly1305_ietf_abytes, libsodium), Csize_t, ())
end

function crypto_aead_chacha20poly1305_ietf_messagebytes_max()
    ccall((:crypto_aead_chacha20poly1305_ietf_messagebytes_max, libsodium), Csize_t, ())
end

function crypto_aead_chacha20poly1305_ietf_encrypt(c, clen_p, m, mlen, ad, adlen, nsec, npub, k)
    ccall((:crypto_aead_chacha20poly1305_ietf_encrypt, libsodium), Cint, (Ptr{Cuchar}, Ptr{Culonglong}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), c, clen_p, m, mlen, ad, adlen, nsec, npub, k)
end

function crypto_aead_chacha20poly1305_ietf_decrypt(m, mlen_p, nsec, c, clen, ad, adlen, npub, k)
    ccall((:crypto_aead_chacha20poly1305_ietf_decrypt, libsodium), Cint, (Ptr{Cuchar}, Ptr{Culonglong}, Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), m, mlen_p, nsec, c, clen, ad, adlen, npub, k)
end

function crypto_aead_chacha20poly1305_ietf_encrypt_detached(c, mac, maclen_p, m, mlen, ad, adlen, nsec, npub, k)
    ccall((:crypto_aead_chacha20poly1305_ietf_encrypt_detached, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Culonglong}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), c, mac, maclen_p, m, mlen, ad, adlen, nsec, npub, k)
end

function crypto_aead_chacha20poly1305_ietf_decrypt_detached(m, nsec, c, clen, mac, ad, adlen, npub, k)
    ccall((:crypto_aead_chacha20poly1305_ietf_decrypt_detached, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), m, nsec, c, clen, mac, ad, adlen, npub, k)
end

function crypto_aead_chacha20poly1305_ietf_keygen(k)
    ccall((:crypto_aead_chacha20poly1305_ietf_keygen, libsodium), Cvoid, (Ptr{Cuchar},), k)
end

function crypto_aead_chacha20poly1305_keybytes()
    ccall((:crypto_aead_chacha20poly1305_keybytes, libsodium), Csize_t, ())
end

function crypto_aead_chacha20poly1305_nsecbytes()
    ccall((:crypto_aead_chacha20poly1305_nsecbytes, libsodium), Csize_t, ())
end

function crypto_aead_chacha20poly1305_npubbytes()
    ccall((:crypto_aead_chacha20poly1305_npubbytes, libsodium), Csize_t, ())
end

function crypto_aead_chacha20poly1305_abytes()
    ccall((:crypto_aead_chacha20poly1305_abytes, libsodium), Csize_t, ())
end

function crypto_aead_chacha20poly1305_messagebytes_max()
    ccall((:crypto_aead_chacha20poly1305_messagebytes_max, libsodium), Csize_t, ())
end

function crypto_aead_chacha20poly1305_encrypt(c, clen_p, m, mlen, ad, adlen, nsec, npub, k)
    ccall((:crypto_aead_chacha20poly1305_encrypt, libsodium), Cint, (Ptr{Cuchar}, Ptr{Culonglong}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), c, clen_p, m, mlen, ad, adlen, nsec, npub, k)
end

function crypto_aead_chacha20poly1305_decrypt(m, mlen_p, nsec, c, clen, ad, adlen, npub, k)
    ccall((:crypto_aead_chacha20poly1305_decrypt, libsodium), Cint, (Ptr{Cuchar}, Ptr{Culonglong}, Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), m, mlen_p, nsec, c, clen, ad, adlen, npub, k)
end

function crypto_aead_chacha20poly1305_encrypt_detached(c, mac, maclen_p, m, mlen, ad, adlen, nsec, npub, k)
    ccall((:crypto_aead_chacha20poly1305_encrypt_detached, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Culonglong}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), c, mac, maclen_p, m, mlen, ad, adlen, nsec, npub, k)
end

function crypto_aead_chacha20poly1305_decrypt_detached(m, nsec, c, clen, mac, ad, adlen, npub, k)
    ccall((:crypto_aead_chacha20poly1305_decrypt_detached, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), m, nsec, c, clen, mac, ad, adlen, npub, k)
end

function crypto_aead_chacha20poly1305_keygen(k)
    ccall((:crypto_aead_chacha20poly1305_keygen, libsodium), Cvoid, (Ptr{Cuchar},), k)
end

function crypto_aead_xchacha20poly1305_ietf_keybytes()
    ccall((:crypto_aead_xchacha20poly1305_ietf_keybytes, libsodium), Csize_t, ())
end

function crypto_aead_xchacha20poly1305_ietf_nsecbytes()
    ccall((:crypto_aead_xchacha20poly1305_ietf_nsecbytes, libsodium), Csize_t, ())
end

function crypto_aead_xchacha20poly1305_ietf_npubbytes()
    ccall((:crypto_aead_xchacha20poly1305_ietf_npubbytes, libsodium), Csize_t, ())
end

function crypto_aead_xchacha20poly1305_ietf_abytes()
    ccall((:crypto_aead_xchacha20poly1305_ietf_abytes, libsodium), Csize_t, ())
end

function crypto_aead_xchacha20poly1305_ietf_messagebytes_max()
    ccall((:crypto_aead_xchacha20poly1305_ietf_messagebytes_max, libsodium), Csize_t, ())
end

function crypto_aead_xchacha20poly1305_ietf_encrypt(c, clen_p, m, mlen, ad, adlen, nsec, npub, k)
    ccall((:crypto_aead_xchacha20poly1305_ietf_encrypt, libsodium), Cint, (Ptr{Cuchar}, Ptr{Culonglong}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), c, clen_p, m, mlen, ad, adlen, nsec, npub, k)
end

function crypto_aead_xchacha20poly1305_ietf_decrypt(m, mlen_p, nsec, c, clen, ad, adlen, npub, k)
    ccall((:crypto_aead_xchacha20poly1305_ietf_decrypt, libsodium), Cint, (Ptr{Cuchar}, Ptr{Culonglong}, Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), m, mlen_p, nsec, c, clen, ad, adlen, npub, k)
end

function crypto_aead_xchacha20poly1305_ietf_encrypt_detached(c, mac, maclen_p, m, mlen, ad, adlen, nsec, npub, k)
    ccall((:crypto_aead_xchacha20poly1305_ietf_encrypt_detached, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Culonglong}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), c, mac, maclen_p, m, mlen, ad, adlen, nsec, npub, k)
end

function crypto_aead_xchacha20poly1305_ietf_decrypt_detached(m, nsec, c, clen, mac, ad, adlen, npub, k)
    ccall((:crypto_aead_xchacha20poly1305_ietf_decrypt_detached, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), m, nsec, c, clen, mac, ad, adlen, npub, k)
end

function crypto_aead_xchacha20poly1305_ietf_keygen(k)
    ccall((:crypto_aead_xchacha20poly1305_ietf_keygen, libsodium), Cvoid, (Ptr{Cuchar},), k)
end

struct crypto_hash_sha512_state
    state::NTuple{8, UInt64}
    count::NTuple{2, UInt64}
    buf::NTuple{128, UInt8}
end

function crypto_hash_sha512_statebytes()
    ccall((:crypto_hash_sha512_statebytes, libsodium), Csize_t, ())
end

function crypto_hash_sha512_bytes()
    ccall((:crypto_hash_sha512_bytes, libsodium), Csize_t, ())
end

function crypto_hash_sha512(out, in, inlen)
    ccall((:crypto_hash_sha512, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong), out, in, inlen)
end

function crypto_hash_sha512_init(state)
    ccall((:crypto_hash_sha512_init, libsodium), Cint, (Ptr{crypto_hash_sha512_state},), state)
end

function crypto_hash_sha512_update(state, in, inlen)
    ccall((:crypto_hash_sha512_update, libsodium), Cint, (Ptr{crypto_hash_sha512_state}, Ptr{Cuchar}, Culonglong), state, in, inlen)
end

function crypto_hash_sha512_final(state, out)
    ccall((:crypto_hash_sha512_final, libsodium), Cint, (Ptr{crypto_hash_sha512_state}, Ptr{Cuchar}), state, out)
end

function crypto_auth_hmacsha512_bytes()
    ccall((:crypto_auth_hmacsha512_bytes, libsodium), Csize_t, ())
end

function crypto_auth_hmacsha512_keybytes()
    ccall((:crypto_auth_hmacsha512_keybytes, libsodium), Csize_t, ())
end

function crypto_auth_hmacsha512(out, in, inlen, k)
    ccall((:crypto_auth_hmacsha512, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}), out, in, inlen, k)
end

function crypto_auth_hmacsha512_verify(h, in, inlen, k)
    ccall((:crypto_auth_hmacsha512_verify, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}), h, in, inlen, k)
end

struct crypto_auth_hmacsha512_state
    ictx::crypto_hash_sha512_state
    octx::crypto_hash_sha512_state
end

function crypto_auth_hmacsha512_statebytes()
    ccall((:crypto_auth_hmacsha512_statebytes, libsodium), Csize_t, ())
end

function crypto_auth_hmacsha512_init(state, key, keylen)
    ccall((:crypto_auth_hmacsha512_init, libsodium), Cint, (Ptr{crypto_auth_hmacsha512_state}, Ptr{Cuchar}, Csize_t), state, key, keylen)
end

function crypto_auth_hmacsha512_update(state, in, inlen)
    ccall((:crypto_auth_hmacsha512_update, libsodium), Cint, (Ptr{crypto_auth_hmacsha512_state}, Ptr{Cuchar}, Culonglong), state, in, inlen)
end

function crypto_auth_hmacsha512_final(state, out)
    ccall((:crypto_auth_hmacsha512_final, libsodium), Cint, (Ptr{crypto_auth_hmacsha512_state}, Ptr{Cuchar}), state, out)
end

function crypto_auth_hmacsha512_keygen(k)
    ccall((:crypto_auth_hmacsha512_keygen, libsodium), Cvoid, (Ptr{Cuchar},), k)
end

function crypto_auth_hmacsha512256_bytes()
    ccall((:crypto_auth_hmacsha512256_bytes, libsodium), Csize_t, ())
end

function crypto_auth_hmacsha512256_keybytes()
    ccall((:crypto_auth_hmacsha512256_keybytes, libsodium), Csize_t, ())
end

function crypto_auth_hmacsha512256(out, in, inlen, k)
    ccall((:crypto_auth_hmacsha512256, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}), out, in, inlen, k)
end

function crypto_auth_hmacsha512256_verify(h, in, inlen, k)
    ccall((:crypto_auth_hmacsha512256_verify, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}), h, in, inlen, k)
end

const crypto_auth_hmacsha512256_state = crypto_auth_hmacsha512_state

function crypto_auth_hmacsha512256_statebytes()
    ccall((:crypto_auth_hmacsha512256_statebytes, libsodium), Csize_t, ())
end

function crypto_auth_hmacsha512256_init(state, key, keylen)
    ccall((:crypto_auth_hmacsha512256_init, libsodium), Cint, (Ptr{crypto_auth_hmacsha512256_state}, Ptr{Cuchar}, Csize_t), state, key, keylen)
end

function crypto_auth_hmacsha512256_update(state, in, inlen)
    ccall((:crypto_auth_hmacsha512256_update, libsodium), Cint, (Ptr{crypto_auth_hmacsha512256_state}, Ptr{Cuchar}, Culonglong), state, in, inlen)
end

function crypto_auth_hmacsha512256_final(state, out)
    ccall((:crypto_auth_hmacsha512256_final, libsodium), Cint, (Ptr{crypto_auth_hmacsha512256_state}, Ptr{Cuchar}), state, out)
end

function crypto_auth_hmacsha512256_keygen(k)
    ccall((:crypto_auth_hmacsha512256_keygen, libsodium), Cvoid, (Ptr{Cuchar},), k)
end

function crypto_auth_bytes()
    ccall((:crypto_auth_bytes, libsodium), Csize_t, ())
end

function crypto_auth_keybytes()
    ccall((:crypto_auth_keybytes, libsodium), Csize_t, ())
end

function crypto_auth_primitive()
    ccall((:crypto_auth_primitive, libsodium), Ptr{Cchar}, ())
end

function crypto_auth(out, in, inlen, k)
    ccall((:crypto_auth, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}), out, in, inlen, k)
end

function crypto_auth_verify(h, in, inlen, k)
    ccall((:crypto_auth_verify, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}), h, in, inlen, k)
end

function crypto_auth_keygen(k)
    ccall((:crypto_auth_keygen, libsodium), Cvoid, (Ptr{Cuchar},), k)
end

struct crypto_hash_sha256_state
    state::NTuple{8, UInt32}
    count::UInt64
    buf::NTuple{64, UInt8}
end

function crypto_hash_sha256_statebytes()
    ccall((:crypto_hash_sha256_statebytes, libsodium), Csize_t, ())
end

function crypto_hash_sha256_bytes()
    ccall((:crypto_hash_sha256_bytes, libsodium), Csize_t, ())
end

function crypto_hash_sha256(out, in, inlen)
    ccall((:crypto_hash_sha256, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong), out, in, inlen)
end

function crypto_hash_sha256_init(state)
    ccall((:crypto_hash_sha256_init, libsodium), Cint, (Ptr{crypto_hash_sha256_state},), state)
end

function crypto_hash_sha256_update(state, in, inlen)
    ccall((:crypto_hash_sha256_update, libsodium), Cint, (Ptr{crypto_hash_sha256_state}, Ptr{Cuchar}, Culonglong), state, in, inlen)
end

function crypto_hash_sha256_final(state, out)
    ccall((:crypto_hash_sha256_final, libsodium), Cint, (Ptr{crypto_hash_sha256_state}, Ptr{Cuchar}), state, out)
end

function crypto_auth_hmacsha256_bytes()
    ccall((:crypto_auth_hmacsha256_bytes, libsodium), Csize_t, ())
end

function crypto_auth_hmacsha256_keybytes()
    ccall((:crypto_auth_hmacsha256_keybytes, libsodium), Csize_t, ())
end

function crypto_auth_hmacsha256(out, in, inlen, k)
    ccall((:crypto_auth_hmacsha256, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}), out, in, inlen, k)
end

function crypto_auth_hmacsha256_verify(h, in, inlen, k)
    ccall((:crypto_auth_hmacsha256_verify, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}), h, in, inlen, k)
end

struct crypto_auth_hmacsha256_state
    ictx::crypto_hash_sha256_state
    octx::crypto_hash_sha256_state
end

function crypto_auth_hmacsha256_statebytes()
    ccall((:crypto_auth_hmacsha256_statebytes, libsodium), Csize_t, ())
end

function crypto_auth_hmacsha256_init(state, key, keylen)
    ccall((:crypto_auth_hmacsha256_init, libsodium), Cint, (Ptr{crypto_auth_hmacsha256_state}, Ptr{Cuchar}, Csize_t), state, key, keylen)
end

function crypto_auth_hmacsha256_update(state, in, inlen)
    ccall((:crypto_auth_hmacsha256_update, libsodium), Cint, (Ptr{crypto_auth_hmacsha256_state}, Ptr{Cuchar}, Culonglong), state, in, inlen)
end

function crypto_auth_hmacsha256_final(state, out)
    ccall((:crypto_auth_hmacsha256_final, libsodium), Cint, (Ptr{crypto_auth_hmacsha256_state}, Ptr{Cuchar}), state, out)
end

function crypto_auth_hmacsha256_keygen(k)
    ccall((:crypto_auth_hmacsha256_keygen, libsodium), Cvoid, (Ptr{Cuchar},), k)
end

function crypto_stream_xsalsa20_keybytes()
    ccall((:crypto_stream_xsalsa20_keybytes, libsodium), Csize_t, ())
end

function crypto_stream_xsalsa20_noncebytes()
    ccall((:crypto_stream_xsalsa20_noncebytes, libsodium), Csize_t, ())
end

function crypto_stream_xsalsa20_messagebytes_max()
    ccall((:crypto_stream_xsalsa20_messagebytes_max, libsodium), Csize_t, ())
end

function crypto_stream_xsalsa20(c, clen, n, k)
    ccall((:crypto_stream_xsalsa20, libsodium), Cint, (Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), c, clen, n, k)
end

function crypto_stream_xsalsa20_xor(c, m, mlen, n, k)
    ccall((:crypto_stream_xsalsa20_xor, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), c, m, mlen, n, k)
end

function crypto_stream_xsalsa20_xor_ic(c, m, mlen, n, ic, k)
    ccall((:crypto_stream_xsalsa20_xor_ic, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, UInt64, Ptr{Cuchar}), c, m, mlen, n, ic, k)
end

function crypto_stream_xsalsa20_keygen(k)
    ccall((:crypto_stream_xsalsa20_keygen, libsodium), Cvoid, (Ptr{Cuchar},), k)
end

function crypto_box_curve25519xsalsa20poly1305_seedbytes()
    ccall((:crypto_box_curve25519xsalsa20poly1305_seedbytes, libsodium), Csize_t, ())
end

function crypto_box_curve25519xsalsa20poly1305_publickeybytes()
    ccall((:crypto_box_curve25519xsalsa20poly1305_publickeybytes, libsodium), Csize_t, ())
end

function crypto_box_curve25519xsalsa20poly1305_secretkeybytes()
    ccall((:crypto_box_curve25519xsalsa20poly1305_secretkeybytes, libsodium), Csize_t, ())
end

function crypto_box_curve25519xsalsa20poly1305_beforenmbytes()
    ccall((:crypto_box_curve25519xsalsa20poly1305_beforenmbytes, libsodium), Csize_t, ())
end

function crypto_box_curve25519xsalsa20poly1305_noncebytes()
    ccall((:crypto_box_curve25519xsalsa20poly1305_noncebytes, libsodium), Csize_t, ())
end

function crypto_box_curve25519xsalsa20poly1305_macbytes()
    ccall((:crypto_box_curve25519xsalsa20poly1305_macbytes, libsodium), Csize_t, ())
end

function crypto_box_curve25519xsalsa20poly1305_messagebytes_max()
    ccall((:crypto_box_curve25519xsalsa20poly1305_messagebytes_max, libsodium), Csize_t, ())
end

function crypto_box_curve25519xsalsa20poly1305_seed_keypair(pk, sk, seed)
    ccall((:crypto_box_curve25519xsalsa20poly1305_seed_keypair, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), pk, sk, seed)
end

function crypto_box_curve25519xsalsa20poly1305_keypair(pk, sk)
    ccall((:crypto_box_curve25519xsalsa20poly1305_keypair, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}), pk, sk)
end

function crypto_box_curve25519xsalsa20poly1305_beforenm(k, pk, sk)
    ccall((:crypto_box_curve25519xsalsa20poly1305_beforenm, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), k, pk, sk)
end

function crypto_box_curve25519xsalsa20poly1305_boxzerobytes()
    ccall((:crypto_box_curve25519xsalsa20poly1305_boxzerobytes, libsodium), Csize_t, ())
end

function crypto_box_curve25519xsalsa20poly1305_zerobytes()
    ccall((:crypto_box_curve25519xsalsa20poly1305_zerobytes, libsodium), Csize_t, ())
end

function crypto_box_curve25519xsalsa20poly1305(c, m, mlen, n, pk, sk)
    ccall((:crypto_box_curve25519xsalsa20poly1305, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), c, m, mlen, n, pk, sk)
end

function crypto_box_curve25519xsalsa20poly1305_open(m, c, clen, n, pk, sk)
    ccall((:crypto_box_curve25519xsalsa20poly1305_open, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), m, c, clen, n, pk, sk)
end

function crypto_box_curve25519xsalsa20poly1305_afternm(c, m, mlen, n, k)
    ccall((:crypto_box_curve25519xsalsa20poly1305_afternm, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), c, m, mlen, n, k)
end

function crypto_box_curve25519xsalsa20poly1305_open_afternm(m, c, clen, n, k)
    ccall((:crypto_box_curve25519xsalsa20poly1305_open_afternm, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), m, c, clen, n, k)
end

function crypto_box_seedbytes()
    ccall((:crypto_box_seedbytes, libsodium), Csize_t, ())
end

function crypto_box_publickeybytes()
    ccall((:crypto_box_publickeybytes, libsodium), Csize_t, ())
end

function crypto_box_secretkeybytes()
    ccall((:crypto_box_secretkeybytes, libsodium), Csize_t, ())
end

function crypto_box_noncebytes()
    ccall((:crypto_box_noncebytes, libsodium), Csize_t, ())
end

function crypto_box_macbytes()
    ccall((:crypto_box_macbytes, libsodium), Csize_t, ())
end

function crypto_box_messagebytes_max()
    ccall((:crypto_box_messagebytes_max, libsodium), Csize_t, ())
end

function crypto_box_primitive()
    ccall((:crypto_box_primitive, libsodium), Ptr{Cchar}, ())
end

function crypto_box_seed_keypair(pk, sk, seed)
    ccall((:crypto_box_seed_keypair, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), pk, sk, seed)
end

function crypto_box_keypair(pk, sk)
    ccall((:crypto_box_keypair, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}), pk, sk)
end

function crypto_box_easy(c, m, mlen, n, pk, sk)
    ccall((:crypto_box_easy, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), c, m, mlen, n, pk, sk)
end

function crypto_box_open_easy(m, c, clen, n, pk, sk)
    ccall((:crypto_box_open_easy, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), m, c, clen, n, pk, sk)
end

function crypto_box_detached(c, mac, m, mlen, n, pk, sk)
    ccall((:crypto_box_detached, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), c, mac, m, mlen, n, pk, sk)
end

function crypto_box_open_detached(m, c, mac, clen, n, pk, sk)
    ccall((:crypto_box_open_detached, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), m, c, mac, clen, n, pk, sk)
end

function crypto_box_beforenmbytes()
    ccall((:crypto_box_beforenmbytes, libsodium), Csize_t, ())
end

function crypto_box_beforenm(k, pk, sk)
    ccall((:crypto_box_beforenm, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), k, pk, sk)
end

function crypto_box_easy_afternm(c, m, mlen, n, k)
    ccall((:crypto_box_easy_afternm, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), c, m, mlen, n, k)
end

function crypto_box_open_easy_afternm(m, c, clen, n, k)
    ccall((:crypto_box_open_easy_afternm, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), m, c, clen, n, k)
end

function crypto_box_detached_afternm(c, mac, m, mlen, n, k)
    ccall((:crypto_box_detached_afternm, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), c, mac, m, mlen, n, k)
end

function crypto_box_open_detached_afternm(m, c, mac, clen, n, k)
    ccall((:crypto_box_open_detached_afternm, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), m, c, mac, clen, n, k)
end

function crypto_box_sealbytes()
    ccall((:crypto_box_sealbytes, libsodium), Csize_t, ())
end

function crypto_box_seal(c, m, mlen, pk)
    ccall((:crypto_box_seal, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}), c, m, mlen, pk)
end

function crypto_box_seal_open(m, c, clen, pk, sk)
    ccall((:crypto_box_seal_open, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), m, c, clen, pk, sk)
end

function crypto_box_zerobytes()
    ccall((:crypto_box_zerobytes, libsodium), Csize_t, ())
end

function crypto_box_boxzerobytes()
    ccall((:crypto_box_boxzerobytes, libsodium), Csize_t, ())
end

function crypto_box(c, m, mlen, n, pk, sk)
    ccall((:crypto_box, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), c, m, mlen, n, pk, sk)
end

function crypto_box_open(m, c, clen, n, pk, sk)
    ccall((:crypto_box_open, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), m, c, clen, n, pk, sk)
end

function crypto_box_afternm(c, m, mlen, n, k)
    ccall((:crypto_box_afternm, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), c, m, mlen, n, k)
end

function crypto_box_open_afternm(m, c, clen, n, k)
    ccall((:crypto_box_open_afternm, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), m, c, clen, n, k)
end

function crypto_core_hsalsa20_outputbytes()
    ccall((:crypto_core_hsalsa20_outputbytes, libsodium), Csize_t, ())
end

function crypto_core_hsalsa20_inputbytes()
    ccall((:crypto_core_hsalsa20_inputbytes, libsodium), Csize_t, ())
end

function crypto_core_hsalsa20_keybytes()
    ccall((:crypto_core_hsalsa20_keybytes, libsodium), Csize_t, ())
end

function crypto_core_hsalsa20_constbytes()
    ccall((:crypto_core_hsalsa20_constbytes, libsodium), Csize_t, ())
end

function crypto_core_hsalsa20(out, in, k, c)
    ccall((:crypto_core_hsalsa20, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), out, in, k, c)
end

function crypto_core_hchacha20_outputbytes()
    ccall((:crypto_core_hchacha20_outputbytes, libsodium), Csize_t, ())
end

function crypto_core_hchacha20_inputbytes()
    ccall((:crypto_core_hchacha20_inputbytes, libsodium), Csize_t, ())
end

function crypto_core_hchacha20_keybytes()
    ccall((:crypto_core_hchacha20_keybytes, libsodium), Csize_t, ())
end

function crypto_core_hchacha20_constbytes()
    ccall((:crypto_core_hchacha20_constbytes, libsodium), Csize_t, ())
end

function crypto_core_hchacha20(out, in, k, c)
    ccall((:crypto_core_hchacha20, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), out, in, k, c)
end

function crypto_core_salsa20_outputbytes()
    ccall((:crypto_core_salsa20_outputbytes, libsodium), Csize_t, ())
end

function crypto_core_salsa20_inputbytes()
    ccall((:crypto_core_salsa20_inputbytes, libsodium), Csize_t, ())
end

function crypto_core_salsa20_keybytes()
    ccall((:crypto_core_salsa20_keybytes, libsodium), Csize_t, ())
end

function crypto_core_salsa20_constbytes()
    ccall((:crypto_core_salsa20_constbytes, libsodium), Csize_t, ())
end

function crypto_core_salsa20(out, in, k, c)
    ccall((:crypto_core_salsa20, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), out, in, k, c)
end

function crypto_core_salsa2012_outputbytes()
    ccall((:crypto_core_salsa2012_outputbytes, libsodium), Csize_t, ())
end

function crypto_core_salsa2012_inputbytes()
    ccall((:crypto_core_salsa2012_inputbytes, libsodium), Csize_t, ())
end

function crypto_core_salsa2012_keybytes()
    ccall((:crypto_core_salsa2012_keybytes, libsodium), Csize_t, ())
end

function crypto_core_salsa2012_constbytes()
    ccall((:crypto_core_salsa2012_constbytes, libsodium), Csize_t, ())
end

function crypto_core_salsa2012(out, in, k, c)
    ccall((:crypto_core_salsa2012, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), out, in, k, c)
end

function crypto_core_salsa208_outputbytes()
    ccall((:crypto_core_salsa208_outputbytes, libsodium), Csize_t, ())
end

function crypto_core_salsa208_inputbytes()
    ccall((:crypto_core_salsa208_inputbytes, libsodium), Csize_t, ())
end

function crypto_core_salsa208_keybytes()
    ccall((:crypto_core_salsa208_keybytes, libsodium), Csize_t, ())
end

function crypto_core_salsa208_constbytes()
    ccall((:crypto_core_salsa208_constbytes, libsodium), Csize_t, ())
end

function crypto_core_salsa208(out, in, k, c)
    ccall((:crypto_core_salsa208, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), out, in, k, c)
end

struct crypto_generichash_blake2b_state
    data::NTuple{384, UInt8}
end

function Base.getproperty(x::Ptr{crypto_generichash_blake2b_state}, f::Symbol)
    f === :opaque && return Ptr{NTuple{384, Cuchar}}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::crypto_generichash_blake2b_state, f::Symbol)
    r = Ref{crypto_generichash_blake2b_state}(x)
    ptr = Base.unsafe_convert(Ptr{crypto_generichash_blake2b_state}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{crypto_generichash_blake2b_state}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function crypto_generichash_blake2b_bytes_min()
    ccall((:crypto_generichash_blake2b_bytes_min, libsodium), Csize_t, ())
end

function crypto_generichash_blake2b_bytes_max()
    ccall((:crypto_generichash_blake2b_bytes_max, libsodium), Csize_t, ())
end

function crypto_generichash_blake2b_bytes()
    ccall((:crypto_generichash_blake2b_bytes, libsodium), Csize_t, ())
end

function crypto_generichash_blake2b_keybytes_min()
    ccall((:crypto_generichash_blake2b_keybytes_min, libsodium), Csize_t, ())
end

function crypto_generichash_blake2b_keybytes_max()
    ccall((:crypto_generichash_blake2b_keybytes_max, libsodium), Csize_t, ())
end

function crypto_generichash_blake2b_keybytes()
    ccall((:crypto_generichash_blake2b_keybytes, libsodium), Csize_t, ())
end

function crypto_generichash_blake2b_saltbytes()
    ccall((:crypto_generichash_blake2b_saltbytes, libsodium), Csize_t, ())
end

function crypto_generichash_blake2b_personalbytes()
    ccall((:crypto_generichash_blake2b_personalbytes, libsodium), Csize_t, ())
end

function crypto_generichash_blake2b_statebytes()
    ccall((:crypto_generichash_blake2b_statebytes, libsodium), Csize_t, ())
end

function crypto_generichash_blake2b(out, outlen, in, inlen, key, keylen)
    ccall((:crypto_generichash_blake2b, libsodium), Cint, (Ptr{Cuchar}, Csize_t, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Csize_t), out, outlen, in, inlen, key, keylen)
end

function crypto_generichash_blake2b_salt_personal(out, outlen, in, inlen, key, keylen, salt, personal)
    ccall((:crypto_generichash_blake2b_salt_personal, libsodium), Cint, (Ptr{Cuchar}, Csize_t, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Csize_t, Ptr{Cuchar}, Ptr{Cuchar}), out, outlen, in, inlen, key, keylen, salt, personal)
end

function crypto_generichash_blake2b_init(state, key, keylen, outlen)
    ccall((:crypto_generichash_blake2b_init, libsodium), Cint, (Ptr{crypto_generichash_blake2b_state}, Ptr{Cuchar}, Csize_t, Csize_t), state, key, keylen, outlen)
end

function crypto_generichash_blake2b_init_salt_personal(state, key, keylen, outlen, salt, personal)
    ccall((:crypto_generichash_blake2b_init_salt_personal, libsodium), Cint, (Ptr{crypto_generichash_blake2b_state}, Ptr{Cuchar}, Csize_t, Csize_t, Ptr{Cuchar}, Ptr{Cuchar}), state, key, keylen, outlen, salt, personal)
end

function crypto_generichash_blake2b_update(state, in, inlen)
    ccall((:crypto_generichash_blake2b_update, libsodium), Cint, (Ptr{crypto_generichash_blake2b_state}, Ptr{Cuchar}, Culonglong), state, in, inlen)
end

function crypto_generichash_blake2b_final(state, out, outlen)
    ccall((:crypto_generichash_blake2b_final, libsodium), Cint, (Ptr{crypto_generichash_blake2b_state}, Ptr{Cuchar}, Csize_t), state, out, outlen)
end

function crypto_generichash_blake2b_keygen(k)
    ccall((:crypto_generichash_blake2b_keygen, libsodium), Cvoid, (Ptr{Cuchar},), k)
end

function crypto_generichash_bytes_min()
    ccall((:crypto_generichash_bytes_min, libsodium), Csize_t, ())
end

function crypto_generichash_bytes_max()
    ccall((:crypto_generichash_bytes_max, libsodium), Csize_t, ())
end

function crypto_generichash_bytes()
    ccall((:crypto_generichash_bytes, libsodium), Csize_t, ())
end

function crypto_generichash_keybytes_min()
    ccall((:crypto_generichash_keybytes_min, libsodium), Csize_t, ())
end

function crypto_generichash_keybytes_max()
    ccall((:crypto_generichash_keybytes_max, libsodium), Csize_t, ())
end

function crypto_generichash_keybytes()
    ccall((:crypto_generichash_keybytes, libsodium), Csize_t, ())
end

function crypto_generichash_primitive()
    ccall((:crypto_generichash_primitive, libsodium), Ptr{Cchar}, ())
end

const crypto_generichash_state = crypto_generichash_blake2b_state

function crypto_generichash_statebytes()
    ccall((:crypto_generichash_statebytes, libsodium), Csize_t, ())
end

function crypto_generichash(out, outlen, in, inlen, key, keylen)
    ccall((:crypto_generichash, libsodium), Cint, (Ptr{Cuchar}, Csize_t, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Csize_t), out, outlen, in, inlen, key, keylen)
end

function crypto_generichash_init(state, key, keylen, outlen)
    ccall((:crypto_generichash_init, libsodium), Cint, (Ptr{crypto_generichash_state}, Ptr{Cuchar}, Csize_t, Csize_t), state, key, keylen, outlen)
end

function crypto_generichash_update(state, in, inlen)
    ccall((:crypto_generichash_update, libsodium), Cint, (Ptr{crypto_generichash_state}, Ptr{Cuchar}, Culonglong), state, in, inlen)
end

function crypto_generichash_final(state, out, outlen)
    ccall((:crypto_generichash_final, libsodium), Cint, (Ptr{crypto_generichash_state}, Ptr{Cuchar}, Csize_t), state, out, outlen)
end

function crypto_generichash_keygen(k)
    ccall((:crypto_generichash_keygen, libsodium), Cvoid, (Ptr{Cuchar},), k)
end

function crypto_hash_bytes()
    ccall((:crypto_hash_bytes, libsodium), Csize_t, ())
end

function crypto_hash(out, in, inlen)
    ccall((:crypto_hash, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong), out, in, inlen)
end

function crypto_hash_primitive()
    ccall((:crypto_hash_primitive, libsodium), Ptr{Cchar}, ())
end

function crypto_kdf_blake2b_bytes_min()
    ccall((:crypto_kdf_blake2b_bytes_min, libsodium), Csize_t, ())
end

function crypto_kdf_blake2b_bytes_max()
    ccall((:crypto_kdf_blake2b_bytes_max, libsodium), Csize_t, ())
end

function crypto_kdf_blake2b_contextbytes()
    ccall((:crypto_kdf_blake2b_contextbytes, libsodium), Csize_t, ())
end

function crypto_kdf_blake2b_keybytes()
    ccall((:crypto_kdf_blake2b_keybytes, libsodium), Csize_t, ())
end

function crypto_kdf_blake2b_derive_from_key(subkey, subkey_len, subkey_id, ctx, key)
    ccall((:crypto_kdf_blake2b_derive_from_key, libsodium), Cint, (Ptr{Cuchar}, Csize_t, UInt64, Ptr{Cchar}, Ptr{Cuchar}), subkey, subkey_len, subkey_id, ctx, key)
end

function crypto_kdf_bytes_min()
    ccall((:crypto_kdf_bytes_min, libsodium), Csize_t, ())
end

function crypto_kdf_bytes_max()
    ccall((:crypto_kdf_bytes_max, libsodium), Csize_t, ())
end

function crypto_kdf_contextbytes()
    ccall((:crypto_kdf_contextbytes, libsodium), Csize_t, ())
end

function crypto_kdf_keybytes()
    ccall((:crypto_kdf_keybytes, libsodium), Csize_t, ())
end

function crypto_kdf_primitive()
    ccall((:crypto_kdf_primitive, libsodium), Ptr{Cchar}, ())
end

function crypto_kdf_derive_from_key(subkey, subkey_len, subkey_id, ctx, key)
    ccall((:crypto_kdf_derive_from_key, libsodium), Cint, (Ptr{Cuchar}, Csize_t, UInt64, Ptr{Cchar}, Ptr{Cuchar}), subkey, subkey_len, subkey_id, ctx, key)
end

function crypto_kdf_keygen(k)
    ccall((:crypto_kdf_keygen, libsodium), Cvoid, (Ptr{Cuchar},), k)
end

function crypto_kx_publickeybytes()
    ccall((:crypto_kx_publickeybytes, libsodium), Csize_t, ())
end

function crypto_kx_secretkeybytes()
    ccall((:crypto_kx_secretkeybytes, libsodium), Csize_t, ())
end

function crypto_kx_seedbytes()
    ccall((:crypto_kx_seedbytes, libsodium), Csize_t, ())
end

function crypto_kx_sessionkeybytes()
    ccall((:crypto_kx_sessionkeybytes, libsodium), Csize_t, ())
end

function crypto_kx_primitive()
    ccall((:crypto_kx_primitive, libsodium), Ptr{Cchar}, ())
end

function crypto_kx_seed_keypair(pk, sk, seed)
    ccall((:crypto_kx_seed_keypair, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), pk, sk, seed)
end

function crypto_kx_keypair(pk, sk)
    ccall((:crypto_kx_keypair, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}), pk, sk)
end

function crypto_kx_client_session_keys(rx, tx, client_pk, client_sk, server_pk)
    ccall((:crypto_kx_client_session_keys, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), rx, tx, client_pk, client_sk, server_pk)
end

function crypto_kx_server_session_keys(rx, tx, server_pk, server_sk, client_pk)
    ccall((:crypto_kx_server_session_keys, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), rx, tx, server_pk, server_sk, client_pk)
end

struct crypto_onetimeauth_poly1305_state
    data::NTuple{256, UInt8}
end

function Base.getproperty(x::Ptr{crypto_onetimeauth_poly1305_state}, f::Symbol)
    f === :opaque && return Ptr{NTuple{256, Cuchar}}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::crypto_onetimeauth_poly1305_state, f::Symbol)
    r = Ref{crypto_onetimeauth_poly1305_state}(x)
    ptr = Base.unsafe_convert(Ptr{crypto_onetimeauth_poly1305_state}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{crypto_onetimeauth_poly1305_state}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function crypto_onetimeauth_poly1305_statebytes()
    ccall((:crypto_onetimeauth_poly1305_statebytes, libsodium), Csize_t, ())
end

function crypto_onetimeauth_poly1305_bytes()
    ccall((:crypto_onetimeauth_poly1305_bytes, libsodium), Csize_t, ())
end

function crypto_onetimeauth_poly1305_keybytes()
    ccall((:crypto_onetimeauth_poly1305_keybytes, libsodium), Csize_t, ())
end

function crypto_onetimeauth_poly1305(out, in, inlen, k)
    ccall((:crypto_onetimeauth_poly1305, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}), out, in, inlen, k)
end

function crypto_onetimeauth_poly1305_verify(h, in, inlen, k)
    ccall((:crypto_onetimeauth_poly1305_verify, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}), h, in, inlen, k)
end

function crypto_onetimeauth_poly1305_init(state, key)
    ccall((:crypto_onetimeauth_poly1305_init, libsodium), Cint, (Ptr{crypto_onetimeauth_poly1305_state}, Ptr{Cuchar}), state, key)
end

function crypto_onetimeauth_poly1305_update(state, in, inlen)
    ccall((:crypto_onetimeauth_poly1305_update, libsodium), Cint, (Ptr{crypto_onetimeauth_poly1305_state}, Ptr{Cuchar}, Culonglong), state, in, inlen)
end

function crypto_onetimeauth_poly1305_final(state, out)
    ccall((:crypto_onetimeauth_poly1305_final, libsodium), Cint, (Ptr{crypto_onetimeauth_poly1305_state}, Ptr{Cuchar}), state, out)
end

function crypto_onetimeauth_poly1305_keygen(k)
    ccall((:crypto_onetimeauth_poly1305_keygen, libsodium), Cvoid, (Ptr{Cuchar},), k)
end

const crypto_onetimeauth_state = crypto_onetimeauth_poly1305_state

function crypto_onetimeauth_statebytes()
    ccall((:crypto_onetimeauth_statebytes, libsodium), Csize_t, ())
end

function crypto_onetimeauth_bytes()
    ccall((:crypto_onetimeauth_bytes, libsodium), Csize_t, ())
end

function crypto_onetimeauth_keybytes()
    ccall((:crypto_onetimeauth_keybytes, libsodium), Csize_t, ())
end

function crypto_onetimeauth_primitive()
    ccall((:crypto_onetimeauth_primitive, libsodium), Ptr{Cchar}, ())
end

function crypto_onetimeauth(out, in, inlen, k)
    ccall((:crypto_onetimeauth, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}), out, in, inlen, k)
end

function crypto_onetimeauth_verify(h, in, inlen, k)
    ccall((:crypto_onetimeauth_verify, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}), h, in, inlen, k)
end

function crypto_onetimeauth_init(state, key)
    ccall((:crypto_onetimeauth_init, libsodium), Cint, (Ptr{crypto_onetimeauth_state}, Ptr{Cuchar}), state, key)
end

function crypto_onetimeauth_update(state, in, inlen)
    ccall((:crypto_onetimeauth_update, libsodium), Cint, (Ptr{crypto_onetimeauth_state}, Ptr{Cuchar}, Culonglong), state, in, inlen)
end

function crypto_onetimeauth_final(state, out)
    ccall((:crypto_onetimeauth_final, libsodium), Cint, (Ptr{crypto_onetimeauth_state}, Ptr{Cuchar}), state, out)
end

function crypto_onetimeauth_keygen(k)
    ccall((:crypto_onetimeauth_keygen, libsodium), Cvoid, (Ptr{Cuchar},), k)
end

function crypto_pwhash_argon2i_alg_argon2i13()
    ccall((:crypto_pwhash_argon2i_alg_argon2i13, libsodium), Cint, ())
end

function crypto_pwhash_argon2i_bytes_min()
    ccall((:crypto_pwhash_argon2i_bytes_min, libsodium), Csize_t, ())
end

function crypto_pwhash_argon2i_bytes_max()
    ccall((:crypto_pwhash_argon2i_bytes_max, libsodium), Csize_t, ())
end

function crypto_pwhash_argon2i_passwd_min()
    ccall((:crypto_pwhash_argon2i_passwd_min, libsodium), Csize_t, ())
end

function crypto_pwhash_argon2i_passwd_max()
    ccall((:crypto_pwhash_argon2i_passwd_max, libsodium), Csize_t, ())
end

function crypto_pwhash_argon2i_saltbytes()
    ccall((:crypto_pwhash_argon2i_saltbytes, libsodium), Csize_t, ())
end

function crypto_pwhash_argon2i_strbytes()
    ccall((:crypto_pwhash_argon2i_strbytes, libsodium), Csize_t, ())
end

function crypto_pwhash_argon2i_strprefix()
    ccall((:crypto_pwhash_argon2i_strprefix, libsodium), Ptr{Cchar}, ())
end

function crypto_pwhash_argon2i_opslimit_min()
    ccall((:crypto_pwhash_argon2i_opslimit_min, libsodium), Csize_t, ())
end

function crypto_pwhash_argon2i_opslimit_max()
    ccall((:crypto_pwhash_argon2i_opslimit_max, libsodium), Csize_t, ())
end

function crypto_pwhash_argon2i_memlimit_min()
    ccall((:crypto_pwhash_argon2i_memlimit_min, libsodium), Csize_t, ())
end

function crypto_pwhash_argon2i_memlimit_max()
    ccall((:crypto_pwhash_argon2i_memlimit_max, libsodium), Csize_t, ())
end

function crypto_pwhash_argon2i_opslimit_interactive()
    ccall((:crypto_pwhash_argon2i_opslimit_interactive, libsodium), Csize_t, ())
end

function crypto_pwhash_argon2i_memlimit_interactive()
    ccall((:crypto_pwhash_argon2i_memlimit_interactive, libsodium), Csize_t, ())
end

function crypto_pwhash_argon2i_opslimit_moderate()
    ccall((:crypto_pwhash_argon2i_opslimit_moderate, libsodium), Csize_t, ())
end

function crypto_pwhash_argon2i_memlimit_moderate()
    ccall((:crypto_pwhash_argon2i_memlimit_moderate, libsodium), Csize_t, ())
end

function crypto_pwhash_argon2i_opslimit_sensitive()
    ccall((:crypto_pwhash_argon2i_opslimit_sensitive, libsodium), Csize_t, ())
end

function crypto_pwhash_argon2i_memlimit_sensitive()
    ccall((:crypto_pwhash_argon2i_memlimit_sensitive, libsodium), Csize_t, ())
end

function crypto_pwhash_argon2i(out, outlen, passwd, passwdlen, salt, opslimit, memlimit, alg)
    ccall((:crypto_pwhash_argon2i, libsodium), Cint, (Ptr{Cuchar}, Culonglong, Ptr{Cchar}, Culonglong, Ptr{Cuchar}, Culonglong, Csize_t, Cint), out, outlen, passwd, passwdlen, salt, opslimit, memlimit, alg)
end

function crypto_pwhash_argon2i_str(out, passwd, passwdlen, opslimit, memlimit)
    ccall((:crypto_pwhash_argon2i_str, libsodium), Cint, (Ptr{Cchar}, Ptr{Cchar}, Culonglong, Culonglong, Csize_t), out, passwd, passwdlen, opslimit, memlimit)
end

function crypto_pwhash_argon2i_str_verify(str, passwd, passwdlen)
    ccall((:crypto_pwhash_argon2i_str_verify, libsodium), Cint, (Ptr{Cchar}, Ptr{Cchar}, Culonglong), str, passwd, passwdlen)
end

function crypto_pwhash_argon2i_str_needs_rehash(str, opslimit, memlimit)
    ccall((:crypto_pwhash_argon2i_str_needs_rehash, libsodium), Cint, (Ptr{Cchar}, Culonglong, Csize_t), str, opslimit, memlimit)
end

function crypto_pwhash_argon2id_alg_argon2id13()
    ccall((:crypto_pwhash_argon2id_alg_argon2id13, libsodium), Cint, ())
end

function crypto_pwhash_argon2id_bytes_min()
    ccall((:crypto_pwhash_argon2id_bytes_min, libsodium), Csize_t, ())
end

function crypto_pwhash_argon2id_bytes_max()
    ccall((:crypto_pwhash_argon2id_bytes_max, libsodium), Csize_t, ())
end

function crypto_pwhash_argon2id_passwd_min()
    ccall((:crypto_pwhash_argon2id_passwd_min, libsodium), Csize_t, ())
end

function crypto_pwhash_argon2id_passwd_max()
    ccall((:crypto_pwhash_argon2id_passwd_max, libsodium), Csize_t, ())
end

function crypto_pwhash_argon2id_saltbytes()
    ccall((:crypto_pwhash_argon2id_saltbytes, libsodium), Csize_t, ())
end

function crypto_pwhash_argon2id_strbytes()
    ccall((:crypto_pwhash_argon2id_strbytes, libsodium), Csize_t, ())
end

function crypto_pwhash_argon2id_strprefix()
    ccall((:crypto_pwhash_argon2id_strprefix, libsodium), Ptr{Cchar}, ())
end

function crypto_pwhash_argon2id_opslimit_min()
    ccall((:crypto_pwhash_argon2id_opslimit_min, libsodium), Csize_t, ())
end

function crypto_pwhash_argon2id_opslimit_max()
    ccall((:crypto_pwhash_argon2id_opslimit_max, libsodium), Csize_t, ())
end

function crypto_pwhash_argon2id_memlimit_min()
    ccall((:crypto_pwhash_argon2id_memlimit_min, libsodium), Csize_t, ())
end

function crypto_pwhash_argon2id_memlimit_max()
    ccall((:crypto_pwhash_argon2id_memlimit_max, libsodium), Csize_t, ())
end

function crypto_pwhash_argon2id_opslimit_interactive()
    ccall((:crypto_pwhash_argon2id_opslimit_interactive, libsodium), Csize_t, ())
end

function crypto_pwhash_argon2id_memlimit_interactive()
    ccall((:crypto_pwhash_argon2id_memlimit_interactive, libsodium), Csize_t, ())
end

function crypto_pwhash_argon2id_opslimit_moderate()
    ccall((:crypto_pwhash_argon2id_opslimit_moderate, libsodium), Csize_t, ())
end

function crypto_pwhash_argon2id_memlimit_moderate()
    ccall((:crypto_pwhash_argon2id_memlimit_moderate, libsodium), Csize_t, ())
end

function crypto_pwhash_argon2id_opslimit_sensitive()
    ccall((:crypto_pwhash_argon2id_opslimit_sensitive, libsodium), Csize_t, ())
end

function crypto_pwhash_argon2id_memlimit_sensitive()
    ccall((:crypto_pwhash_argon2id_memlimit_sensitive, libsodium), Csize_t, ())
end

function crypto_pwhash_argon2id(out, outlen, passwd, passwdlen, salt, opslimit, memlimit, alg)
    ccall((:crypto_pwhash_argon2id, libsodium), Cint, (Ptr{Cuchar}, Culonglong, Ptr{Cchar}, Culonglong, Ptr{Cuchar}, Culonglong, Csize_t, Cint), out, outlen, passwd, passwdlen, salt, opslimit, memlimit, alg)
end

function crypto_pwhash_argon2id_str(out, passwd, passwdlen, opslimit, memlimit)
    ccall((:crypto_pwhash_argon2id_str, libsodium), Cint, (Ptr{Cchar}, Ptr{Cchar}, Culonglong, Culonglong, Csize_t), out, passwd, passwdlen, opslimit, memlimit)
end

function crypto_pwhash_argon2id_str_verify(str, passwd, passwdlen)
    ccall((:crypto_pwhash_argon2id_str_verify, libsodium), Cint, (Ptr{Cchar}, Ptr{Cchar}, Culonglong), str, passwd, passwdlen)
end

function crypto_pwhash_argon2id_str_needs_rehash(str, opslimit, memlimit)
    ccall((:crypto_pwhash_argon2id_str_needs_rehash, libsodium), Cint, (Ptr{Cchar}, Culonglong, Csize_t), str, opslimit, memlimit)
end

function crypto_pwhash_alg_argon2i13()
    ccall((:crypto_pwhash_alg_argon2i13, libsodium), Cint, ())
end

function crypto_pwhash_alg_argon2id13()
    ccall((:crypto_pwhash_alg_argon2id13, libsodium), Cint, ())
end

function crypto_pwhash_alg_default()
    ccall((:crypto_pwhash_alg_default, libsodium), Cint, ())
end

function crypto_pwhash_bytes_min()
    ccall((:crypto_pwhash_bytes_min, libsodium), Csize_t, ())
end

function crypto_pwhash_bytes_max()
    ccall((:crypto_pwhash_bytes_max, libsodium), Csize_t, ())
end

function crypto_pwhash_passwd_min()
    ccall((:crypto_pwhash_passwd_min, libsodium), Csize_t, ())
end

function crypto_pwhash_passwd_max()
    ccall((:crypto_pwhash_passwd_max, libsodium), Csize_t, ())
end

function crypto_pwhash_saltbytes()
    ccall((:crypto_pwhash_saltbytes, libsodium), Csize_t, ())
end

function crypto_pwhash_strbytes()
    ccall((:crypto_pwhash_strbytes, libsodium), Csize_t, ())
end

function crypto_pwhash_strprefix()
    ccall((:crypto_pwhash_strprefix, libsodium), Ptr{Cchar}, ())
end

function crypto_pwhash_opslimit_min()
    ccall((:crypto_pwhash_opslimit_min, libsodium), Csize_t, ())
end

function crypto_pwhash_opslimit_max()
    ccall((:crypto_pwhash_opslimit_max, libsodium), Csize_t, ())
end

function crypto_pwhash_memlimit_min()
    ccall((:crypto_pwhash_memlimit_min, libsodium), Csize_t, ())
end

function crypto_pwhash_memlimit_max()
    ccall((:crypto_pwhash_memlimit_max, libsodium), Csize_t, ())
end

function crypto_pwhash_opslimit_interactive()
    ccall((:crypto_pwhash_opslimit_interactive, libsodium), Csize_t, ())
end

function crypto_pwhash_memlimit_interactive()
    ccall((:crypto_pwhash_memlimit_interactive, libsodium), Csize_t, ())
end

function crypto_pwhash_opslimit_moderate()
    ccall((:crypto_pwhash_opslimit_moderate, libsodium), Csize_t, ())
end

function crypto_pwhash_memlimit_moderate()
    ccall((:crypto_pwhash_memlimit_moderate, libsodium), Csize_t, ())
end

function crypto_pwhash_opslimit_sensitive()
    ccall((:crypto_pwhash_opslimit_sensitive, libsodium), Csize_t, ())
end

function crypto_pwhash_memlimit_sensitive()
    ccall((:crypto_pwhash_memlimit_sensitive, libsodium), Csize_t, ())
end

function crypto_pwhash(out, outlen, passwd, passwdlen, salt, opslimit, memlimit, alg)
    ccall((:crypto_pwhash, libsodium), Cint, (Ptr{Cuchar}, Culonglong, Ptr{Cchar}, Culonglong, Ptr{Cuchar}, Culonglong, Csize_t, Cint), out, outlen, passwd, passwdlen, salt, opslimit, memlimit, alg)
end

function crypto_pwhash_str(out, passwd, passwdlen, opslimit, memlimit)
    ccall((:crypto_pwhash_str, libsodium), Cint, (Ptr{Cchar}, Ptr{Cchar}, Culonglong, Culonglong, Csize_t), out, passwd, passwdlen, opslimit, memlimit)
end

function crypto_pwhash_str_alg(out, passwd, passwdlen, opslimit, memlimit, alg)
    ccall((:crypto_pwhash_str_alg, libsodium), Cint, (Ptr{Cchar}, Ptr{Cchar}, Culonglong, Culonglong, Csize_t, Cint), out, passwd, passwdlen, opslimit, memlimit, alg)
end

function crypto_pwhash_str_verify(str, passwd, passwdlen)
    ccall((:crypto_pwhash_str_verify, libsodium), Cint, (Ptr{Cchar}, Ptr{Cchar}, Culonglong), str, passwd, passwdlen)
end

function crypto_pwhash_str_needs_rehash(str, opslimit, memlimit)
    ccall((:crypto_pwhash_str_needs_rehash, libsodium), Cint, (Ptr{Cchar}, Culonglong, Csize_t), str, opslimit, memlimit)
end

function crypto_pwhash_primitive()
    ccall((:crypto_pwhash_primitive, libsodium), Ptr{Cchar}, ())
end

function crypto_scalarmult_curve25519_bytes()
    ccall((:crypto_scalarmult_curve25519_bytes, libsodium), Csize_t, ())
end

function crypto_scalarmult_curve25519_scalarbytes()
    ccall((:crypto_scalarmult_curve25519_scalarbytes, libsodium), Csize_t, ())
end

function crypto_scalarmult_curve25519(q, n, p)
    ccall((:crypto_scalarmult_curve25519, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), q, n, p)
end

function crypto_scalarmult_curve25519_base(q, n)
    ccall((:crypto_scalarmult_curve25519_base, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}), q, n)
end

function crypto_scalarmult_bytes()
    ccall((:crypto_scalarmult_bytes, libsodium), Csize_t, ())
end

function crypto_scalarmult_scalarbytes()
    ccall((:crypto_scalarmult_scalarbytes, libsodium), Csize_t, ())
end

function crypto_scalarmult_primitive()
    ccall((:crypto_scalarmult_primitive, libsodium), Ptr{Cchar}, ())
end

function crypto_scalarmult_base(q, n)
    ccall((:crypto_scalarmult_base, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}), q, n)
end

function crypto_scalarmult(q, n, p)
    ccall((:crypto_scalarmult, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), q, n, p)
end

function crypto_secretbox_xsalsa20poly1305_keybytes()
    ccall((:crypto_secretbox_xsalsa20poly1305_keybytes, libsodium), Csize_t, ())
end

function crypto_secretbox_xsalsa20poly1305_noncebytes()
    ccall((:crypto_secretbox_xsalsa20poly1305_noncebytes, libsodium), Csize_t, ())
end

function crypto_secretbox_xsalsa20poly1305_macbytes()
    ccall((:crypto_secretbox_xsalsa20poly1305_macbytes, libsodium), Csize_t, ())
end

function crypto_secretbox_xsalsa20poly1305_messagebytes_max()
    ccall((:crypto_secretbox_xsalsa20poly1305_messagebytes_max, libsodium), Csize_t, ())
end

function crypto_secretbox_xsalsa20poly1305(c, m, mlen, n, k)
    ccall((:crypto_secretbox_xsalsa20poly1305, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), c, m, mlen, n, k)
end

function crypto_secretbox_xsalsa20poly1305_open(m, c, clen, n, k)
    ccall((:crypto_secretbox_xsalsa20poly1305_open, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), m, c, clen, n, k)
end

function crypto_secretbox_xsalsa20poly1305_keygen(k)
    ccall((:crypto_secretbox_xsalsa20poly1305_keygen, libsodium), Cvoid, (Ptr{Cuchar},), k)
end

function crypto_secretbox_xsalsa20poly1305_boxzerobytes()
    ccall((:crypto_secretbox_xsalsa20poly1305_boxzerobytes, libsodium), Csize_t, ())
end

function crypto_secretbox_xsalsa20poly1305_zerobytes()
    ccall((:crypto_secretbox_xsalsa20poly1305_zerobytes, libsodium), Csize_t, ())
end

function crypto_secretbox_keybytes()
    ccall((:crypto_secretbox_keybytes, libsodium), Csize_t, ())
end

function crypto_secretbox_noncebytes()
    ccall((:crypto_secretbox_noncebytes, libsodium), Csize_t, ())
end

function crypto_secretbox_macbytes()
    ccall((:crypto_secretbox_macbytes, libsodium), Csize_t, ())
end

function crypto_secretbox_primitive()
    ccall((:crypto_secretbox_primitive, libsodium), Ptr{Cchar}, ())
end

function crypto_secretbox_messagebytes_max()
    ccall((:crypto_secretbox_messagebytes_max, libsodium), Csize_t, ())
end

function crypto_secretbox_easy(c, m, mlen, n, k)
    ccall((:crypto_secretbox_easy, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), c, m, mlen, n, k)
end

function crypto_secretbox_open_easy(m, c, clen, n, k)
    ccall((:crypto_secretbox_open_easy, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), m, c, clen, n, k)
end

function crypto_secretbox_detached(c, mac, m, mlen, n, k)
    ccall((:crypto_secretbox_detached, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), c, mac, m, mlen, n, k)
end

function crypto_secretbox_open_detached(m, c, mac, clen, n, k)
    ccall((:crypto_secretbox_open_detached, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), m, c, mac, clen, n, k)
end

function crypto_secretbox_keygen(k)
    ccall((:crypto_secretbox_keygen, libsodium), Cvoid, (Ptr{Cuchar},), k)
end

function crypto_secretbox_zerobytes()
    ccall((:crypto_secretbox_zerobytes, libsodium), Csize_t, ())
end

function crypto_secretbox_boxzerobytes()
    ccall((:crypto_secretbox_boxzerobytes, libsodium), Csize_t, ())
end

function crypto_secretbox(c, m, mlen, n, k)
    ccall((:crypto_secretbox, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), c, m, mlen, n, k)
end

function crypto_secretbox_open(m, c, clen, n, k)
    ccall((:crypto_secretbox_open, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), m, c, clen, n, k)
end

function crypto_stream_chacha20_keybytes()
    ccall((:crypto_stream_chacha20_keybytes, libsodium), Csize_t, ())
end

function crypto_stream_chacha20_noncebytes()
    ccall((:crypto_stream_chacha20_noncebytes, libsodium), Csize_t, ())
end

function crypto_stream_chacha20_messagebytes_max()
    ccall((:crypto_stream_chacha20_messagebytes_max, libsodium), Csize_t, ())
end

function crypto_stream_chacha20(c, clen, n, k)
    ccall((:crypto_stream_chacha20, libsodium), Cint, (Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), c, clen, n, k)
end

function crypto_stream_chacha20_xor(c, m, mlen, n, k)
    ccall((:crypto_stream_chacha20_xor, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), c, m, mlen, n, k)
end

function crypto_stream_chacha20_xor_ic(c, m, mlen, n, ic, k)
    ccall((:crypto_stream_chacha20_xor_ic, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, UInt64, Ptr{Cuchar}), c, m, mlen, n, ic, k)
end

function crypto_stream_chacha20_keygen(k)
    ccall((:crypto_stream_chacha20_keygen, libsodium), Cvoid, (Ptr{Cuchar},), k)
end

function crypto_stream_chacha20_ietf_keybytes()
    ccall((:crypto_stream_chacha20_ietf_keybytes, libsodium), Csize_t, ())
end

function crypto_stream_chacha20_ietf_noncebytes()
    ccall((:crypto_stream_chacha20_ietf_noncebytes, libsodium), Csize_t, ())
end

function crypto_stream_chacha20_ietf_messagebytes_max()
    ccall((:crypto_stream_chacha20_ietf_messagebytes_max, libsodium), Csize_t, ())
end

function crypto_stream_chacha20_ietf(c, clen, n, k)
    ccall((:crypto_stream_chacha20_ietf, libsodium), Cint, (Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), c, clen, n, k)
end

function crypto_stream_chacha20_ietf_xor(c, m, mlen, n, k)
    ccall((:crypto_stream_chacha20_ietf_xor, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), c, m, mlen, n, k)
end

function crypto_stream_chacha20_ietf_xor_ic(c, m, mlen, n, ic, k)
    ccall((:crypto_stream_chacha20_ietf_xor_ic, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, UInt32, Ptr{Cuchar}), c, m, mlen, n, ic, k)
end

function crypto_stream_chacha20_ietf_keygen(k)
    ccall((:crypto_stream_chacha20_ietf_keygen, libsodium), Cvoid, (Ptr{Cuchar},), k)
end

function crypto_secretstream_xchacha20poly1305_abytes()
    ccall((:crypto_secretstream_xchacha20poly1305_abytes, libsodium), Csize_t, ())
end

function crypto_secretstream_xchacha20poly1305_headerbytes()
    ccall((:crypto_secretstream_xchacha20poly1305_headerbytes, libsodium), Csize_t, ())
end

function crypto_secretstream_xchacha20poly1305_keybytes()
    ccall((:crypto_secretstream_xchacha20poly1305_keybytes, libsodium), Csize_t, ())
end

function crypto_secretstream_xchacha20poly1305_messagebytes_max()
    ccall((:crypto_secretstream_xchacha20poly1305_messagebytes_max, libsodium), Csize_t, ())
end

function crypto_secretstream_xchacha20poly1305_tag_message()
    ccall((:crypto_secretstream_xchacha20poly1305_tag_message, libsodium), Cuchar, ())
end

function crypto_secretstream_xchacha20poly1305_tag_push()
    ccall((:crypto_secretstream_xchacha20poly1305_tag_push, libsodium), Cuchar, ())
end

function crypto_secretstream_xchacha20poly1305_tag_rekey()
    ccall((:crypto_secretstream_xchacha20poly1305_tag_rekey, libsodium), Cuchar, ())
end

function crypto_secretstream_xchacha20poly1305_tag_final()
    ccall((:crypto_secretstream_xchacha20poly1305_tag_final, libsodium), Cuchar, ())
end

struct crypto_secretstream_xchacha20poly1305_state
    k::NTuple{32, Cuchar}
    nonce::NTuple{12, Cuchar}
    _pad::NTuple{8, Cuchar}
end

function crypto_secretstream_xchacha20poly1305_statebytes()
    ccall((:crypto_secretstream_xchacha20poly1305_statebytes, libsodium), Csize_t, ())
end

function crypto_secretstream_xchacha20poly1305_keygen(k)
    ccall((:crypto_secretstream_xchacha20poly1305_keygen, libsodium), Cvoid, (Ptr{Cuchar},), k)
end

function crypto_secretstream_xchacha20poly1305_init_push(state, header, k)
    ccall((:crypto_secretstream_xchacha20poly1305_init_push, libsodium), Cint, (Ptr{crypto_secretstream_xchacha20poly1305_state}, Ptr{Cuchar}, Ptr{Cuchar}), state, header, k)
end

function crypto_secretstream_xchacha20poly1305_push(state, c, clen_p, m, mlen, ad, adlen, tag)
    ccall((:crypto_secretstream_xchacha20poly1305_push, libsodium), Cint, (Ptr{crypto_secretstream_xchacha20poly1305_state}, Ptr{Cuchar}, Ptr{Culonglong}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Culonglong, Cuchar), state, c, clen_p, m, mlen, ad, adlen, tag)
end

function crypto_secretstream_xchacha20poly1305_init_pull(state, header, k)
    ccall((:crypto_secretstream_xchacha20poly1305_init_pull, libsodium), Cint, (Ptr{crypto_secretstream_xchacha20poly1305_state}, Ptr{Cuchar}, Ptr{Cuchar}), state, header, k)
end

function crypto_secretstream_xchacha20poly1305_pull(state, m, mlen_p, tag_p, c, clen, ad, adlen)
    ccall((:crypto_secretstream_xchacha20poly1305_pull, libsodium), Cint, (Ptr{crypto_secretstream_xchacha20poly1305_state}, Ptr{Cuchar}, Ptr{Culonglong}, Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Culonglong), state, m, mlen_p, tag_p, c, clen, ad, adlen)
end

function crypto_secretstream_xchacha20poly1305_rekey(state)
    ccall((:crypto_secretstream_xchacha20poly1305_rekey, libsodium), Cvoid, (Ptr{crypto_secretstream_xchacha20poly1305_state},), state)
end

function crypto_shorthash_siphash24_bytes()
    ccall((:crypto_shorthash_siphash24_bytes, libsodium), Csize_t, ())
end

function crypto_shorthash_siphash24_keybytes()
    ccall((:crypto_shorthash_siphash24_keybytes, libsodium), Csize_t, ())
end

function crypto_shorthash_siphash24(out, in, inlen, k)
    ccall((:crypto_shorthash_siphash24, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}), out, in, inlen, k)
end

function crypto_shorthash_siphashx24_bytes()
    ccall((:crypto_shorthash_siphashx24_bytes, libsodium), Csize_t, ())
end

function crypto_shorthash_siphashx24_keybytes()
    ccall((:crypto_shorthash_siphashx24_keybytes, libsodium), Csize_t, ())
end

function crypto_shorthash_siphashx24(out, in, inlen, k)
    ccall((:crypto_shorthash_siphashx24, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}), out, in, inlen, k)
end

function crypto_shorthash_bytes()
    ccall((:crypto_shorthash_bytes, libsodium), Csize_t, ())
end

function crypto_shorthash_keybytes()
    ccall((:crypto_shorthash_keybytes, libsodium), Csize_t, ())
end

function crypto_shorthash_primitive()
    ccall((:crypto_shorthash_primitive, libsodium), Ptr{Cchar}, ())
end

function crypto_shorthash(out, in, inlen, k)
    ccall((:crypto_shorthash, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}), out, in, inlen, k)
end

function crypto_shorthash_keygen(k)
    ccall((:crypto_shorthash_keygen, libsodium), Cvoid, (Ptr{Cuchar},), k)
end

struct crypto_sign_ed25519ph_state
    hs::crypto_hash_sha512_state
end

function crypto_sign_ed25519ph_statebytes()
    ccall((:crypto_sign_ed25519ph_statebytes, libsodium), Csize_t, ())
end

function crypto_sign_ed25519_bytes()
    ccall((:crypto_sign_ed25519_bytes, libsodium), Csize_t, ())
end

function crypto_sign_ed25519_seedbytes()
    ccall((:crypto_sign_ed25519_seedbytes, libsodium), Csize_t, ())
end

function crypto_sign_ed25519_publickeybytes()
    ccall((:crypto_sign_ed25519_publickeybytes, libsodium), Csize_t, ())
end

function crypto_sign_ed25519_secretkeybytes()
    ccall((:crypto_sign_ed25519_secretkeybytes, libsodium), Csize_t, ())
end

function crypto_sign_ed25519_messagebytes_max()
    ccall((:crypto_sign_ed25519_messagebytes_max, libsodium), Csize_t, ())
end

function crypto_sign_ed25519(sm, smlen_p, m, mlen, sk)
    ccall((:crypto_sign_ed25519, libsodium), Cint, (Ptr{Cuchar}, Ptr{Culonglong}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}), sm, smlen_p, m, mlen, sk)
end

function crypto_sign_ed25519_open(m, mlen_p, sm, smlen, pk)
    ccall((:crypto_sign_ed25519_open, libsodium), Cint, (Ptr{Cuchar}, Ptr{Culonglong}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}), m, mlen_p, sm, smlen, pk)
end

function crypto_sign_ed25519_detached(sig, siglen_p, m, mlen, sk)
    ccall((:crypto_sign_ed25519_detached, libsodium), Cint, (Ptr{Cuchar}, Ptr{Culonglong}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}), sig, siglen_p, m, mlen, sk)
end

function crypto_sign_ed25519_verify_detached(sig, m, mlen, pk)
    ccall((:crypto_sign_ed25519_verify_detached, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}), sig, m, mlen, pk)
end

function crypto_sign_ed25519_keypair(pk, sk)
    ccall((:crypto_sign_ed25519_keypair, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}), pk, sk)
end

function crypto_sign_ed25519_seed_keypair(pk, sk, seed)
    ccall((:crypto_sign_ed25519_seed_keypair, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), pk, sk, seed)
end

function crypto_sign_ed25519_pk_to_curve25519(curve25519_pk, ed25519_pk)
    ccall((:crypto_sign_ed25519_pk_to_curve25519, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}), curve25519_pk, ed25519_pk)
end

function crypto_sign_ed25519_sk_to_curve25519(curve25519_sk, ed25519_sk)
    ccall((:crypto_sign_ed25519_sk_to_curve25519, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}), curve25519_sk, ed25519_sk)
end

function crypto_sign_ed25519_sk_to_seed(seed, sk)
    ccall((:crypto_sign_ed25519_sk_to_seed, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}), seed, sk)
end

function crypto_sign_ed25519_sk_to_pk(pk, sk)
    ccall((:crypto_sign_ed25519_sk_to_pk, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}), pk, sk)
end

function crypto_sign_ed25519ph_init(state)
    ccall((:crypto_sign_ed25519ph_init, libsodium), Cint, (Ptr{crypto_sign_ed25519ph_state},), state)
end

function crypto_sign_ed25519ph_update(state, m, mlen)
    ccall((:crypto_sign_ed25519ph_update, libsodium), Cint, (Ptr{crypto_sign_ed25519ph_state}, Ptr{Cuchar}, Culonglong), state, m, mlen)
end

function crypto_sign_ed25519ph_final_create(state, sig, siglen_p, sk)
    ccall((:crypto_sign_ed25519ph_final_create, libsodium), Cint, (Ptr{crypto_sign_ed25519ph_state}, Ptr{Cuchar}, Ptr{Culonglong}, Ptr{Cuchar}), state, sig, siglen_p, sk)
end

function crypto_sign_ed25519ph_final_verify(state, sig, pk)
    ccall((:crypto_sign_ed25519ph_final_verify, libsodium), Cint, (Ptr{crypto_sign_ed25519ph_state}, Ptr{Cuchar}, Ptr{Cuchar}), state, sig, pk)
end

const crypto_sign_state = crypto_sign_ed25519ph_state

function crypto_sign_statebytes()
    ccall((:crypto_sign_statebytes, libsodium), Csize_t, ())
end

function crypto_sign_bytes()
    ccall((:crypto_sign_bytes, libsodium), Csize_t, ())
end

function crypto_sign_seedbytes()
    ccall((:crypto_sign_seedbytes, libsodium), Csize_t, ())
end

function crypto_sign_publickeybytes()
    ccall((:crypto_sign_publickeybytes, libsodium), Csize_t, ())
end

function crypto_sign_secretkeybytes()
    ccall((:crypto_sign_secretkeybytes, libsodium), Csize_t, ())
end

function crypto_sign_messagebytes_max()
    ccall((:crypto_sign_messagebytes_max, libsodium), Csize_t, ())
end

function crypto_sign_primitive()
    ccall((:crypto_sign_primitive, libsodium), Ptr{Cchar}, ())
end

function crypto_sign_seed_keypair(pk, sk, seed)
    ccall((:crypto_sign_seed_keypair, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), pk, sk, seed)
end

function crypto_sign_keypair(pk, sk)
    ccall((:crypto_sign_keypair, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}), pk, sk)
end

function crypto_sign(sm, smlen_p, m, mlen, sk)
    ccall((:crypto_sign, libsodium), Cint, (Ptr{Cuchar}, Ptr{Culonglong}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}), sm, smlen_p, m, mlen, sk)
end

function crypto_sign_open(m, mlen_p, sm, smlen, pk)
    ccall((:crypto_sign_open, libsodium), Cint, (Ptr{Cuchar}, Ptr{Culonglong}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}), m, mlen_p, sm, smlen, pk)
end

function crypto_sign_detached(sig, siglen_p, m, mlen, sk)
    ccall((:crypto_sign_detached, libsodium), Cint, (Ptr{Cuchar}, Ptr{Culonglong}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}), sig, siglen_p, m, mlen, sk)
end

function crypto_sign_verify_detached(sig, m, mlen, pk)
    ccall((:crypto_sign_verify_detached, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}), sig, m, mlen, pk)
end

function crypto_sign_init(state)
    ccall((:crypto_sign_init, libsodium), Cint, (Ptr{crypto_sign_state},), state)
end

function crypto_sign_update(state, m, mlen)
    ccall((:crypto_sign_update, libsodium), Cint, (Ptr{crypto_sign_state}, Ptr{Cuchar}, Culonglong), state, m, mlen)
end

function crypto_sign_final_create(state, sig, siglen_p, sk)
    ccall((:crypto_sign_final_create, libsodium), Cint, (Ptr{crypto_sign_state}, Ptr{Cuchar}, Ptr{Culonglong}, Ptr{Cuchar}), state, sig, siglen_p, sk)
end

function crypto_sign_final_verify(state, sig, pk)
    ccall((:crypto_sign_final_verify, libsodium), Cint, (Ptr{crypto_sign_state}, Ptr{Cuchar}, Ptr{Cuchar}), state, sig, pk)
end

function crypto_stream_keybytes()
    ccall((:crypto_stream_keybytes, libsodium), Csize_t, ())
end

function crypto_stream_noncebytes()
    ccall((:crypto_stream_noncebytes, libsodium), Csize_t, ())
end

function crypto_stream_messagebytes_max()
    ccall((:crypto_stream_messagebytes_max, libsodium), Csize_t, ())
end

function crypto_stream_primitive()
    ccall((:crypto_stream_primitive, libsodium), Ptr{Cchar}, ())
end

function crypto_stream(c, clen, n, k)
    ccall((:crypto_stream, libsodium), Cint, (Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), c, clen, n, k)
end

function crypto_stream_xor(c, m, mlen, n, k)
    ccall((:crypto_stream_xor, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), c, m, mlen, n, k)
end

function crypto_stream_keygen(k)
    ccall((:crypto_stream_keygen, libsodium), Cvoid, (Ptr{Cuchar},), k)
end

function crypto_stream_salsa20_keybytes()
    ccall((:crypto_stream_salsa20_keybytes, libsodium), Csize_t, ())
end

function crypto_stream_salsa20_noncebytes()
    ccall((:crypto_stream_salsa20_noncebytes, libsodium), Csize_t, ())
end

function crypto_stream_salsa20_messagebytes_max()
    ccall((:crypto_stream_salsa20_messagebytes_max, libsodium), Csize_t, ())
end

function crypto_stream_salsa20(c, clen, n, k)
    ccall((:crypto_stream_salsa20, libsodium), Cint, (Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), c, clen, n, k)
end

function crypto_stream_salsa20_xor(c, m, mlen, n, k)
    ccall((:crypto_stream_salsa20_xor, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), c, m, mlen, n, k)
end

function crypto_stream_salsa20_xor_ic(c, m, mlen, n, ic, k)
    ccall((:crypto_stream_salsa20_xor_ic, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, UInt64, Ptr{Cuchar}), c, m, mlen, n, ic, k)
end

function crypto_stream_salsa20_keygen(k)
    ccall((:crypto_stream_salsa20_keygen, libsodium), Cvoid, (Ptr{Cuchar},), k)
end

function crypto_verify_16_bytes()
    ccall((:crypto_verify_16_bytes, libsodium), Csize_t, ())
end

function crypto_verify_16(x, y)
    ccall((:crypto_verify_16, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}), x, y)
end

function crypto_verify_32_bytes()
    ccall((:crypto_verify_32_bytes, libsodium), Csize_t, ())
end

function crypto_verify_32(x, y)
    ccall((:crypto_verify_32, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}), x, y)
end

function crypto_verify_64_bytes()
    ccall((:crypto_verify_64_bytes, libsodium), Csize_t, ())
end

function crypto_verify_64(x, y)
    ccall((:crypto_verify_64, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}), x, y)
end

struct randombytes_implementation
    implementation_name::Ptr{Cvoid}
    random::Ptr{Cvoid}
    stir::Ptr{Cvoid}
    uniform::Ptr{Cvoid}
    buf::Ptr{Cvoid}
    close::Ptr{Cvoid}
end

function randombytes_seedbytes()
    ccall((:randombytes_seedbytes, libsodium), Csize_t, ())
end

function randombytes_buf(buf, size)
    ccall((:randombytes_buf, libsodium), Cvoid, (Ptr{Cvoid}, Csize_t), buf, size)
end

function randombytes_buf_deterministic(buf, size, seed)
    ccall((:randombytes_buf_deterministic, libsodium), Cvoid, (Ptr{Cvoid}, Csize_t, Ptr{Cuchar}), buf, size, seed)
end

function randombytes_random()
    ccall((:randombytes_random, libsodium), UInt32, ())
end

function randombytes_uniform(upper_bound)
    ccall((:randombytes_uniform, libsodium), UInt32, (UInt32,), upper_bound)
end

function randombytes_stir()
    ccall((:randombytes_stir, libsodium), Cvoid, ())
end

function randombytes_close()
    ccall((:randombytes_close, libsodium), Cint, ())
end

function randombytes_set_implementation(impl)
    ccall((:randombytes_set_implementation, libsodium), Cint, (Ptr{randombytes_implementation},), impl)
end

function randombytes_implementation_name()
    ccall((:randombytes_implementation_name, libsodium), Ptr{Cchar}, ())
end

function randombytes(buf, buf_len)
    ccall((:randombytes, libsodium), Cvoid, (Ptr{Cuchar}, Culonglong), buf, buf_len)
end

function sodium_runtime_has_neon()
    ccall((:sodium_runtime_has_neon, libsodium), Cint, ())
end

function sodium_runtime_has_sse2()
    ccall((:sodium_runtime_has_sse2, libsodium), Cint, ())
end

function sodium_runtime_has_sse3()
    ccall((:sodium_runtime_has_sse3, libsodium), Cint, ())
end

function sodium_runtime_has_ssse3()
    ccall((:sodium_runtime_has_ssse3, libsodium), Cint, ())
end

function sodium_runtime_has_sse41()
    ccall((:sodium_runtime_has_sse41, libsodium), Cint, ())
end

function sodium_runtime_has_avx()
    ccall((:sodium_runtime_has_avx, libsodium), Cint, ())
end

function sodium_runtime_has_avx2()
    ccall((:sodium_runtime_has_avx2, libsodium), Cint, ())
end

function sodium_runtime_has_avx512f()
    ccall((:sodium_runtime_has_avx512f, libsodium), Cint, ())
end

function sodium_runtime_has_pclmul()
    ccall((:sodium_runtime_has_pclmul, libsodium), Cint, ())
end

function sodium_runtime_has_aesni()
    ccall((:sodium_runtime_has_aesni, libsodium), Cint, ())
end

function sodium_runtime_has_rdrand()
    ccall((:sodium_runtime_has_rdrand, libsodium), Cint, ())
end

function _sodium_runtime_get_cpu_features()
    ccall((:_sodium_runtime_get_cpu_features, libsodium), Cint, ())
end

function sodium_memzero(pnt, len)
    ccall((:sodium_memzero, libsodium), Cvoid, (Ptr{Cvoid}, Csize_t), pnt, len)
end

function sodium_stackzero(len)
    ccall((:sodium_stackzero, libsodium), Cvoid, (Csize_t,), len)
end

function sodium_memcmp(b1_, b2_, len)
    ccall((:sodium_memcmp, libsodium), Cint, (Ptr{Cvoid}, Ptr{Cvoid}, Csize_t), b1_, b2_, len)
end

function sodium_compare(b1_, b2_, len)
    ccall((:sodium_compare, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Csize_t), b1_, b2_, len)
end

function sodium_is_zero(n, nlen)
    ccall((:sodium_is_zero, libsodium), Cint, (Ptr{Cuchar}, Csize_t), n, nlen)
end

function sodium_increment(n, nlen)
    ccall((:sodium_increment, libsodium), Cvoid, (Ptr{Cuchar}, Csize_t), n, nlen)
end

function sodium_add(a, b, len)
    ccall((:sodium_add, libsodium), Cvoid, (Ptr{Cuchar}, Ptr{Cuchar}, Csize_t), a, b, len)
end

function sodium_sub(a, b, len)
    ccall((:sodium_sub, libsodium), Cvoid, (Ptr{Cuchar}, Ptr{Cuchar}, Csize_t), a, b, len)
end

function sodium_bin2hex(hex, hex_maxlen, bin, bin_len)
    ccall((:sodium_bin2hex, libsodium), Ptr{Cchar}, (Ptr{Cchar}, Csize_t, Ptr{Cuchar}, Csize_t), hex, hex_maxlen, bin, bin_len)
end

function sodium_hex2bin(bin, bin_maxlen, hex, hex_len, ignore, bin_len, hex_end)
    ccall((:sodium_hex2bin, libsodium), Cint, (Ptr{Cuchar}, Csize_t, Ptr{Cchar}, Csize_t, Ptr{Cchar}, Ptr{Csize_t}, Ptr{Ptr{Cchar}}), bin, bin_maxlen, hex, hex_len, ignore, bin_len, hex_end)
end

function sodium_base64_encoded_len(bin_len, variant)
    ccall((:sodium_base64_encoded_len, libsodium), Csize_t, (Csize_t, Cint), bin_len, variant)
end

function sodium_bin2base64(b64, b64_maxlen, bin, bin_len, variant)
    ccall((:sodium_bin2base64, libsodium), Ptr{Cchar}, (Ptr{Cchar}, Csize_t, Ptr{Cuchar}, Csize_t, Cint), b64, b64_maxlen, bin, bin_len, variant)
end

function sodium_base642bin(bin, bin_maxlen, b64, b64_len, ignore, bin_len, b64_end, variant)
    ccall((:sodium_base642bin, libsodium), Cint, (Ptr{Cuchar}, Csize_t, Ptr{Cchar}, Csize_t, Ptr{Cchar}, Ptr{Csize_t}, Ptr{Ptr{Cchar}}, Cint), bin, bin_maxlen, b64, b64_len, ignore, bin_len, b64_end, variant)
end

function sodium_mlock(addr, len)
    ccall((:sodium_mlock, libsodium), Cint, (Ptr{Cvoid}, Csize_t), addr, len)
end

function sodium_munlock(addr, len)
    ccall((:sodium_munlock, libsodium), Cint, (Ptr{Cvoid}, Csize_t), addr, len)
end

function sodium_malloc(size)
    ccall((:sodium_malloc, libsodium), Ptr{Cvoid}, (Csize_t,), size)
end

function sodium_allocarray(count, size)
    ccall((:sodium_allocarray, libsodium), Ptr{Cvoid}, (Csize_t, Csize_t), count, size)
end

function sodium_free(ptr)
    ccall((:sodium_free, libsodium), Cvoid, (Ptr{Cvoid},), ptr)
end

function sodium_mprotect_noaccess(ptr)
    ccall((:sodium_mprotect_noaccess, libsodium), Cint, (Ptr{Cvoid},), ptr)
end

function sodium_mprotect_readonly(ptr)
    ccall((:sodium_mprotect_readonly, libsodium), Cint, (Ptr{Cvoid},), ptr)
end

function sodium_mprotect_readwrite(ptr)
    ccall((:sodium_mprotect_readwrite, libsodium), Cint, (Ptr{Cvoid},), ptr)
end

function sodium_pad(padded_buflen_p, buf, unpadded_buflen, blocksize, max_buflen)
    ccall((:sodium_pad, libsodium), Cint, (Ptr{Csize_t}, Ptr{Cuchar}, Csize_t, Csize_t, Csize_t), padded_buflen_p, buf, unpadded_buflen, blocksize, max_buflen)
end

function sodium_unpad(unpadded_buflen_p, buf, padded_buflen, blocksize)
    ccall((:sodium_unpad, libsodium), Cint, (Ptr{Csize_t}, Ptr{Cuchar}, Csize_t, Csize_t), unpadded_buflen_p, buf, padded_buflen, blocksize)
end

function _sodium_alloc_init()
    ccall((:_sodium_alloc_init, libsodium), Cint, ())
end

function crypto_stream_xchacha20_keybytes()
    ccall((:crypto_stream_xchacha20_keybytes, libsodium), Csize_t, ())
end

function crypto_stream_xchacha20_noncebytes()
    ccall((:crypto_stream_xchacha20_noncebytes, libsodium), Csize_t, ())
end

function crypto_stream_xchacha20_messagebytes_max()
    ccall((:crypto_stream_xchacha20_messagebytes_max, libsodium), Csize_t, ())
end

function crypto_stream_xchacha20(c, clen, n, k)
    ccall((:crypto_stream_xchacha20, libsodium), Cint, (Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), c, clen, n, k)
end

function crypto_stream_xchacha20_xor(c, m, mlen, n, k)
    ccall((:crypto_stream_xchacha20_xor, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), c, m, mlen, n, k)
end

function crypto_stream_xchacha20_xor_ic(c, m, mlen, n, ic, k)
    ccall((:crypto_stream_xchacha20_xor_ic, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, UInt64, Ptr{Cuchar}), c, m, mlen, n, ic, k)
end

function crypto_stream_xchacha20_keygen(k)
    ccall((:crypto_stream_xchacha20_keygen, libsodium), Cvoid, (Ptr{Cuchar},), k)
end

function crypto_box_curve25519xchacha20poly1305_seedbytes()
    ccall((:crypto_box_curve25519xchacha20poly1305_seedbytes, libsodium), Csize_t, ())
end

function crypto_box_curve25519xchacha20poly1305_publickeybytes()
    ccall((:crypto_box_curve25519xchacha20poly1305_publickeybytes, libsodium), Csize_t, ())
end

function crypto_box_curve25519xchacha20poly1305_secretkeybytes()
    ccall((:crypto_box_curve25519xchacha20poly1305_secretkeybytes, libsodium), Csize_t, ())
end

function crypto_box_curve25519xchacha20poly1305_beforenmbytes()
    ccall((:crypto_box_curve25519xchacha20poly1305_beforenmbytes, libsodium), Csize_t, ())
end

function crypto_box_curve25519xchacha20poly1305_noncebytes()
    ccall((:crypto_box_curve25519xchacha20poly1305_noncebytes, libsodium), Csize_t, ())
end

function crypto_box_curve25519xchacha20poly1305_macbytes()
    ccall((:crypto_box_curve25519xchacha20poly1305_macbytes, libsodium), Csize_t, ())
end

function crypto_box_curve25519xchacha20poly1305_messagebytes_max()
    ccall((:crypto_box_curve25519xchacha20poly1305_messagebytes_max, libsodium), Csize_t, ())
end

function crypto_box_curve25519xchacha20poly1305_seed_keypair(pk, sk, seed)
    ccall((:crypto_box_curve25519xchacha20poly1305_seed_keypair, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), pk, sk, seed)
end

function crypto_box_curve25519xchacha20poly1305_keypair(pk, sk)
    ccall((:crypto_box_curve25519xchacha20poly1305_keypair, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}), pk, sk)
end

function crypto_box_curve25519xchacha20poly1305_easy(c, m, mlen, n, pk, sk)
    ccall((:crypto_box_curve25519xchacha20poly1305_easy, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), c, m, mlen, n, pk, sk)
end

function crypto_box_curve25519xchacha20poly1305_open_easy(m, c, clen, n, pk, sk)
    ccall((:crypto_box_curve25519xchacha20poly1305_open_easy, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), m, c, clen, n, pk, sk)
end

function crypto_box_curve25519xchacha20poly1305_detached(c, mac, m, mlen, n, pk, sk)
    ccall((:crypto_box_curve25519xchacha20poly1305_detached, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), c, mac, m, mlen, n, pk, sk)
end

function crypto_box_curve25519xchacha20poly1305_open_detached(m, c, mac, clen, n, pk, sk)
    ccall((:crypto_box_curve25519xchacha20poly1305_open_detached, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), m, c, mac, clen, n, pk, sk)
end

function crypto_box_curve25519xchacha20poly1305_beforenm(k, pk, sk)
    ccall((:crypto_box_curve25519xchacha20poly1305_beforenm, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), k, pk, sk)
end

function crypto_box_curve25519xchacha20poly1305_easy_afternm(c, m, mlen, n, k)
    ccall((:crypto_box_curve25519xchacha20poly1305_easy_afternm, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), c, m, mlen, n, k)
end

function crypto_box_curve25519xchacha20poly1305_open_easy_afternm(m, c, clen, n, k)
    ccall((:crypto_box_curve25519xchacha20poly1305_open_easy_afternm, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), m, c, clen, n, k)
end

function crypto_box_curve25519xchacha20poly1305_detached_afternm(c, mac, m, mlen, n, k)
    ccall((:crypto_box_curve25519xchacha20poly1305_detached_afternm, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), c, mac, m, mlen, n, k)
end

function crypto_box_curve25519xchacha20poly1305_open_detached_afternm(m, c, mac, clen, n, k)
    ccall((:crypto_box_curve25519xchacha20poly1305_open_detached_afternm, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), m, c, mac, clen, n, k)
end

function crypto_box_curve25519xchacha20poly1305_sealbytes()
    ccall((:crypto_box_curve25519xchacha20poly1305_sealbytes, libsodium), Csize_t, ())
end

function crypto_box_curve25519xchacha20poly1305_seal(c, m, mlen, pk)
    ccall((:crypto_box_curve25519xchacha20poly1305_seal, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}), c, m, mlen, pk)
end

function crypto_box_curve25519xchacha20poly1305_seal_open(m, c, clen, pk, sk)
    ccall((:crypto_box_curve25519xchacha20poly1305_seal_open, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), m, c, clen, pk, sk)
end

function crypto_core_ed25519_bytes()
    ccall((:crypto_core_ed25519_bytes, libsodium), Csize_t, ())
end

function crypto_core_ed25519_uniformbytes()
    ccall((:crypto_core_ed25519_uniformbytes, libsodium), Csize_t, ())
end

function crypto_core_ed25519_hashbytes()
    ccall((:crypto_core_ed25519_hashbytes, libsodium), Csize_t, ())
end

function crypto_core_ed25519_scalarbytes()
    ccall((:crypto_core_ed25519_scalarbytes, libsodium), Csize_t, ())
end

function crypto_core_ed25519_nonreducedscalarbytes()
    ccall((:crypto_core_ed25519_nonreducedscalarbytes, libsodium), Csize_t, ())
end

function crypto_core_ed25519_is_valid_point(p)
    ccall((:crypto_core_ed25519_is_valid_point, libsodium), Cint, (Ptr{Cuchar},), p)
end

function crypto_core_ed25519_add(r, p, q)
    ccall((:crypto_core_ed25519_add, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), r, p, q)
end

function crypto_core_ed25519_sub(r, p, q)
    ccall((:crypto_core_ed25519_sub, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), r, p, q)
end

function crypto_core_ed25519_from_uniform(p, r)
    ccall((:crypto_core_ed25519_from_uniform, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}), p, r)
end

function crypto_core_ed25519_from_hash(p, h)
    ccall((:crypto_core_ed25519_from_hash, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}), p, h)
end

function crypto_core_ed25519_random(p)
    ccall((:crypto_core_ed25519_random, libsodium), Cvoid, (Ptr{Cuchar},), p)
end

function crypto_core_ed25519_scalar_random(r)
    ccall((:crypto_core_ed25519_scalar_random, libsodium), Cvoid, (Ptr{Cuchar},), r)
end

function crypto_core_ed25519_scalar_invert(recip, s)
    ccall((:crypto_core_ed25519_scalar_invert, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}), recip, s)
end

function crypto_core_ed25519_scalar_negate(neg, s)
    ccall((:crypto_core_ed25519_scalar_negate, libsodium), Cvoid, (Ptr{Cuchar}, Ptr{Cuchar}), neg, s)
end

function crypto_core_ed25519_scalar_complement(comp, s)
    ccall((:crypto_core_ed25519_scalar_complement, libsodium), Cvoid, (Ptr{Cuchar}, Ptr{Cuchar}), comp, s)
end

function crypto_core_ed25519_scalar_add(z, x, y)
    ccall((:crypto_core_ed25519_scalar_add, libsodium), Cvoid, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), z, x, y)
end

function crypto_core_ed25519_scalar_sub(z, x, y)
    ccall((:crypto_core_ed25519_scalar_sub, libsodium), Cvoid, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), z, x, y)
end

function crypto_core_ed25519_scalar_mul(z, x, y)
    ccall((:crypto_core_ed25519_scalar_mul, libsodium), Cvoid, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), z, x, y)
end

function crypto_core_ed25519_scalar_reduce(r, s)
    ccall((:crypto_core_ed25519_scalar_reduce, libsodium), Cvoid, (Ptr{Cuchar}, Ptr{Cuchar}), r, s)
end

function crypto_core_ristretto255_bytes()
    ccall((:crypto_core_ristretto255_bytes, libsodium), Csize_t, ())
end

function crypto_core_ristretto255_hashbytes()
    ccall((:crypto_core_ristretto255_hashbytes, libsodium), Csize_t, ())
end

function crypto_core_ristretto255_scalarbytes()
    ccall((:crypto_core_ristretto255_scalarbytes, libsodium), Csize_t, ())
end

function crypto_core_ristretto255_nonreducedscalarbytes()
    ccall((:crypto_core_ristretto255_nonreducedscalarbytes, libsodium), Csize_t, ())
end

function crypto_core_ristretto255_is_valid_point(p)
    ccall((:crypto_core_ristretto255_is_valid_point, libsodium), Cint, (Ptr{Cuchar},), p)
end

function crypto_core_ristretto255_add(r, p, q)
    ccall((:crypto_core_ristretto255_add, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), r, p, q)
end

function crypto_core_ristretto255_sub(r, p, q)
    ccall((:crypto_core_ristretto255_sub, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), r, p, q)
end

function crypto_core_ristretto255_from_hash(p, r)
    ccall((:crypto_core_ristretto255_from_hash, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}), p, r)
end

function crypto_core_ristretto255_random(p)
    ccall((:crypto_core_ristretto255_random, libsodium), Cvoid, (Ptr{Cuchar},), p)
end

function crypto_core_ristretto255_scalar_random(r)
    ccall((:crypto_core_ristretto255_scalar_random, libsodium), Cvoid, (Ptr{Cuchar},), r)
end

function crypto_core_ristretto255_scalar_invert(recip, s)
    ccall((:crypto_core_ristretto255_scalar_invert, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}), recip, s)
end

function crypto_core_ristretto255_scalar_negate(neg, s)
    ccall((:crypto_core_ristretto255_scalar_negate, libsodium), Cvoid, (Ptr{Cuchar}, Ptr{Cuchar}), neg, s)
end

function crypto_core_ristretto255_scalar_complement(comp, s)
    ccall((:crypto_core_ristretto255_scalar_complement, libsodium), Cvoid, (Ptr{Cuchar}, Ptr{Cuchar}), comp, s)
end

function crypto_core_ristretto255_scalar_add(z, x, y)
    ccall((:crypto_core_ristretto255_scalar_add, libsodium), Cvoid, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), z, x, y)
end

function crypto_core_ristretto255_scalar_sub(z, x, y)
    ccall((:crypto_core_ristretto255_scalar_sub, libsodium), Cvoid, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), z, x, y)
end

function crypto_core_ristretto255_scalar_mul(z, x, y)
    ccall((:crypto_core_ristretto255_scalar_mul, libsodium), Cvoid, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), z, x, y)
end

function crypto_core_ristretto255_scalar_reduce(r, s)
    ccall((:crypto_core_ristretto255_scalar_reduce, libsodium), Cvoid, (Ptr{Cuchar}, Ptr{Cuchar}), r, s)
end

function crypto_scalarmult_ed25519_bytes()
    ccall((:crypto_scalarmult_ed25519_bytes, libsodium), Csize_t, ())
end

function crypto_scalarmult_ed25519_scalarbytes()
    ccall((:crypto_scalarmult_ed25519_scalarbytes, libsodium), Csize_t, ())
end

function crypto_scalarmult_ed25519(q, n, p)
    ccall((:crypto_scalarmult_ed25519, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), q, n, p)
end

function crypto_scalarmult_ed25519_noclamp(q, n, p)
    ccall((:crypto_scalarmult_ed25519_noclamp, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), q, n, p)
end

function crypto_scalarmult_ed25519_base(q, n)
    ccall((:crypto_scalarmult_ed25519_base, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}), q, n)
end

function crypto_scalarmult_ed25519_base_noclamp(q, n)
    ccall((:crypto_scalarmult_ed25519_base_noclamp, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}), q, n)
end

function crypto_scalarmult_ristretto255_bytes()
    ccall((:crypto_scalarmult_ristretto255_bytes, libsodium), Csize_t, ())
end

function crypto_scalarmult_ristretto255_scalarbytes()
    ccall((:crypto_scalarmult_ristretto255_scalarbytes, libsodium), Csize_t, ())
end

function crypto_scalarmult_ristretto255(q, n, p)
    ccall((:crypto_scalarmult_ristretto255, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), q, n, p)
end

function crypto_scalarmult_ristretto255_base(q, n)
    ccall((:crypto_scalarmult_ristretto255_base, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}), q, n)
end

function crypto_secretbox_xchacha20poly1305_keybytes()
    ccall((:crypto_secretbox_xchacha20poly1305_keybytes, libsodium), Csize_t, ())
end

function crypto_secretbox_xchacha20poly1305_noncebytes()
    ccall((:crypto_secretbox_xchacha20poly1305_noncebytes, libsodium), Csize_t, ())
end

function crypto_secretbox_xchacha20poly1305_macbytes()
    ccall((:crypto_secretbox_xchacha20poly1305_macbytes, libsodium), Csize_t, ())
end

function crypto_secretbox_xchacha20poly1305_messagebytes_max()
    ccall((:crypto_secretbox_xchacha20poly1305_messagebytes_max, libsodium), Csize_t, ())
end

function crypto_secretbox_xchacha20poly1305_easy(c, m, mlen, n, k)
    ccall((:crypto_secretbox_xchacha20poly1305_easy, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), c, m, mlen, n, k)
end

function crypto_secretbox_xchacha20poly1305_open_easy(m, c, clen, n, k)
    ccall((:crypto_secretbox_xchacha20poly1305_open_easy, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), m, c, clen, n, k)
end

function crypto_secretbox_xchacha20poly1305_detached(c, mac, m, mlen, n, k)
    ccall((:crypto_secretbox_xchacha20poly1305_detached, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), c, mac, m, mlen, n, k)
end

function crypto_secretbox_xchacha20poly1305_open_detached(m, c, mac, clen, n, k)
    ccall((:crypto_secretbox_xchacha20poly1305_open_detached, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), m, c, mac, clen, n, k)
end

function crypto_pwhash_scryptsalsa208sha256_bytes_min()
    ccall((:crypto_pwhash_scryptsalsa208sha256_bytes_min, libsodium), Csize_t, ())
end

function crypto_pwhash_scryptsalsa208sha256_bytes_max()
    ccall((:crypto_pwhash_scryptsalsa208sha256_bytes_max, libsodium), Csize_t, ())
end

function crypto_pwhash_scryptsalsa208sha256_passwd_min()
    ccall((:crypto_pwhash_scryptsalsa208sha256_passwd_min, libsodium), Csize_t, ())
end

function crypto_pwhash_scryptsalsa208sha256_passwd_max()
    ccall((:crypto_pwhash_scryptsalsa208sha256_passwd_max, libsodium), Csize_t, ())
end

function crypto_pwhash_scryptsalsa208sha256_saltbytes()
    ccall((:crypto_pwhash_scryptsalsa208sha256_saltbytes, libsodium), Csize_t, ())
end

function crypto_pwhash_scryptsalsa208sha256_strbytes()
    ccall((:crypto_pwhash_scryptsalsa208sha256_strbytes, libsodium), Csize_t, ())
end

function crypto_pwhash_scryptsalsa208sha256_strprefix()
    ccall((:crypto_pwhash_scryptsalsa208sha256_strprefix, libsodium), Ptr{Cchar}, ())
end

function crypto_pwhash_scryptsalsa208sha256_opslimit_min()
    ccall((:crypto_pwhash_scryptsalsa208sha256_opslimit_min, libsodium), Csize_t, ())
end

function crypto_pwhash_scryptsalsa208sha256_opslimit_max()
    ccall((:crypto_pwhash_scryptsalsa208sha256_opslimit_max, libsodium), Csize_t, ())
end

function crypto_pwhash_scryptsalsa208sha256_memlimit_min()
    ccall((:crypto_pwhash_scryptsalsa208sha256_memlimit_min, libsodium), Csize_t, ())
end

function crypto_pwhash_scryptsalsa208sha256_memlimit_max()
    ccall((:crypto_pwhash_scryptsalsa208sha256_memlimit_max, libsodium), Csize_t, ())
end

function crypto_pwhash_scryptsalsa208sha256_opslimit_interactive()
    ccall((:crypto_pwhash_scryptsalsa208sha256_opslimit_interactive, libsodium), Csize_t, ())
end

function crypto_pwhash_scryptsalsa208sha256_memlimit_interactive()
    ccall((:crypto_pwhash_scryptsalsa208sha256_memlimit_interactive, libsodium), Csize_t, ())
end

function crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive()
    ccall((:crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive, libsodium), Csize_t, ())
end

function crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive()
    ccall((:crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive, libsodium), Csize_t, ())
end

function crypto_pwhash_scryptsalsa208sha256(out, outlen, passwd, passwdlen, salt, opslimit, memlimit)
    ccall((:crypto_pwhash_scryptsalsa208sha256, libsodium), Cint, (Ptr{Cuchar}, Culonglong, Ptr{Cchar}, Culonglong, Ptr{Cuchar}, Culonglong, Csize_t), out, outlen, passwd, passwdlen, salt, opslimit, memlimit)
end

function crypto_pwhash_scryptsalsa208sha256_str(out, passwd, passwdlen, opslimit, memlimit)
    ccall((:crypto_pwhash_scryptsalsa208sha256_str, libsodium), Cint, (Ptr{Cchar}, Ptr{Cchar}, Culonglong, Culonglong, Csize_t), out, passwd, passwdlen, opslimit, memlimit)
end

function crypto_pwhash_scryptsalsa208sha256_str_verify(str, passwd, passwdlen)
    ccall((:crypto_pwhash_scryptsalsa208sha256_str_verify, libsodium), Cint, (Ptr{Cchar}, Ptr{Cchar}, Culonglong), str, passwd, passwdlen)
end

function crypto_pwhash_scryptsalsa208sha256_ll(passwd, passwdlen, salt, saltlen, N, r, p, buf, buflen)
    ccall((:crypto_pwhash_scryptsalsa208sha256_ll, libsodium), Cint, (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, UInt64, UInt32, UInt32, Ptr{UInt8}, Csize_t), passwd, passwdlen, salt, saltlen, N, r, p, buf, buflen)
end

function crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(str, opslimit, memlimit)
    ccall((:crypto_pwhash_scryptsalsa208sha256_str_needs_rehash, libsodium), Cint, (Ptr{Cchar}, Culonglong, Csize_t), str, opslimit, memlimit)
end

function crypto_stream_salsa2012_keybytes()
    ccall((:crypto_stream_salsa2012_keybytes, libsodium), Csize_t, ())
end

function crypto_stream_salsa2012_noncebytes()
    ccall((:crypto_stream_salsa2012_noncebytes, libsodium), Csize_t, ())
end

function crypto_stream_salsa2012_messagebytes_max()
    ccall((:crypto_stream_salsa2012_messagebytes_max, libsodium), Csize_t, ())
end

function crypto_stream_salsa2012(c, clen, n, k)
    ccall((:crypto_stream_salsa2012, libsodium), Cint, (Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), c, clen, n, k)
end

function crypto_stream_salsa2012_xor(c, m, mlen, n, k)
    ccall((:crypto_stream_salsa2012_xor, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), c, m, mlen, n, k)
end

function crypto_stream_salsa2012_keygen(k)
    ccall((:crypto_stream_salsa2012_keygen, libsodium), Cvoid, (Ptr{Cuchar},), k)
end

function crypto_stream_salsa208_keybytes()
    ccall((:crypto_stream_salsa208_keybytes, libsodium), Csize_t, ())
end

function crypto_stream_salsa208_noncebytes()
    ccall((:crypto_stream_salsa208_noncebytes, libsodium), Csize_t, ())
end

function crypto_stream_salsa208_messagebytes_max()
    ccall((:crypto_stream_salsa208_messagebytes_max, libsodium), Csize_t, ())
end

function crypto_stream_salsa208(c, clen, n, k)
    ccall((:crypto_stream_salsa208, libsodium), Cint, (Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), c, clen, n, k)
end

function crypto_stream_salsa208_xor(c, m, mlen, n, k)
    ccall((:crypto_stream_salsa208_xor, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}, Ptr{Cuchar}), c, m, mlen, n, k)
end

function crypto_stream_salsa208_keygen(k)
    ccall((:crypto_stream_salsa208_keygen, libsodium), Cvoid, (Ptr{Cuchar},), k)
end

SODIUM_MIN(A, B) = if A < B
        A
    else
        B
    end

const SODIUM_SIZE_MAX = SODIUM_MIN(UINT64_MAX, SIZE_MAX)

const crypto_sign_edwards25519sha512batch_BYTES = Cuint(64)

const crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES = Cuint(32)

const crypto_sign_edwards25519sha512batch_SECRETKEYBYTES = Cuint(32) + Cuint(32)

const crypto_sign_edwards25519sha512batch_MESSAGEBYTES_MAX = SODIUM_SIZE_MAX - crypto_sign_edwards25519sha512batch_BYTES

const SODIUM_VERSION_STRING = "1.0.18"

const SODIUM_LIBRARY_VERSION_MAJOR = 10

const SODIUM_LIBRARY_VERSION_MINOR = 3

const crypto_aead_aes256gcm_KEYBYTES = Cuint(32)

const crypto_aead_aes256gcm_NSECBYTES = Cuint(0)

const crypto_aead_aes256gcm_NPUBBYTES = Cuint(12)

const crypto_aead_aes256gcm_ABYTES = Cuint(16)

const crypto_aead_aes256gcm_MESSAGEBYTES_MAX = SODIUM_MIN(SODIUM_SIZE_MAX - crypto_aead_aes256gcm_ABYTES, Culonglong(16) * (Culonglong(1) << 32 - Culonglong(2)))

const crypto_aead_chacha20poly1305_ietf_KEYBYTES = Cuint(32)

const crypto_aead_chacha20poly1305_ietf_NSECBYTES = Cuint(0)

const crypto_aead_chacha20poly1305_ietf_NPUBBYTES = Cuint(12)

const crypto_aead_chacha20poly1305_ietf_ABYTES = Cuint(16)

const crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX = SODIUM_MIN(SODIUM_SIZE_MAX - crypto_aead_chacha20poly1305_ietf_ABYTES, Culonglong(64) * (Culonglong(1) << 32 - Culonglong(1)))

const crypto_aead_chacha20poly1305_KEYBYTES = Cuint(32)

const crypto_aead_chacha20poly1305_NSECBYTES = Cuint(0)

const crypto_aead_chacha20poly1305_NPUBBYTES = Cuint(8)

const crypto_aead_chacha20poly1305_ABYTES = Cuint(16)

const crypto_aead_chacha20poly1305_MESSAGEBYTES_MAX = SODIUM_SIZE_MAX - crypto_aead_chacha20poly1305_ABYTES

const crypto_aead_chacha20poly1305_IETF_KEYBYTES = crypto_aead_chacha20poly1305_ietf_KEYBYTES

const crypto_aead_chacha20poly1305_IETF_NSECBYTES = crypto_aead_chacha20poly1305_ietf_NSECBYTES

const crypto_aead_chacha20poly1305_IETF_NPUBBYTES = crypto_aead_chacha20poly1305_ietf_NPUBBYTES

const crypto_aead_chacha20poly1305_IETF_ABYTES = crypto_aead_chacha20poly1305_ietf_ABYTES

const crypto_aead_chacha20poly1305_IETF_MESSAGEBYTES_MAX = crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX

const crypto_aead_xchacha20poly1305_ietf_KEYBYTES = Cuint(32)

const crypto_aead_xchacha20poly1305_ietf_NSECBYTES = Cuint(0)

const crypto_aead_xchacha20poly1305_ietf_NPUBBYTES = Cuint(24)

const crypto_aead_xchacha20poly1305_ietf_ABYTES = Cuint(16)

const crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX = SODIUM_SIZE_MAX - crypto_aead_xchacha20poly1305_ietf_ABYTES

const crypto_aead_xchacha20poly1305_IETF_KEYBYTES = crypto_aead_xchacha20poly1305_ietf_KEYBYTES

const crypto_aead_xchacha20poly1305_IETF_NSECBYTES = crypto_aead_xchacha20poly1305_ietf_NSECBYTES

const crypto_aead_xchacha20poly1305_IETF_NPUBBYTES = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES

const crypto_aead_xchacha20poly1305_IETF_ABYTES = crypto_aead_xchacha20poly1305_ietf_ABYTES

const crypto_aead_xchacha20poly1305_IETF_MESSAGEBYTES_MAX = crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX

const crypto_hash_sha512_BYTES = Cuint(64)

const crypto_auth_hmacsha512_BYTES = Cuint(64)

const crypto_auth_hmacsha512_KEYBYTES = Cuint(32)

const crypto_auth_hmacsha512256_BYTES = Cuint(32)

const crypto_auth_hmacsha512256_KEYBYTES = Cuint(32)

const crypto_auth_BYTES = crypto_auth_hmacsha512256_BYTES

const crypto_auth_KEYBYTES = crypto_auth_hmacsha512256_KEYBYTES

const crypto_auth_PRIMITIVE = "hmacsha512256"

const crypto_hash_sha256_BYTES = Cuint(32)

const crypto_auth_hmacsha256_BYTES = Cuint(32)

const crypto_auth_hmacsha256_KEYBYTES = Cuint(32)

const crypto_stream_xsalsa20_KEYBYTES = Cuint(32)

const crypto_stream_xsalsa20_NONCEBYTES = Cuint(24)

const crypto_stream_xsalsa20_MESSAGEBYTES_MAX = SODIUM_SIZE_MAX

const crypto_box_curve25519xsalsa20poly1305_SEEDBYTES = Cuint(32)

const crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES = Cuint(32)

const crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES = Cuint(32)

const crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES = Cuint(32)

const crypto_box_curve25519xsalsa20poly1305_NONCEBYTES = Cuint(24)

const crypto_box_curve25519xsalsa20poly1305_MACBYTES = Cuint(16)

const crypto_box_curve25519xsalsa20poly1305_MESSAGEBYTES_MAX = crypto_stream_xsalsa20_MESSAGEBYTES_MAX - crypto_box_curve25519xsalsa20poly1305_MACBYTES

const crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES = Cuint(16)

const crypto_box_curve25519xsalsa20poly1305_ZEROBYTES = crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES + crypto_box_curve25519xsalsa20poly1305_MACBYTES

const crypto_box_SEEDBYTES = crypto_box_curve25519xsalsa20poly1305_SEEDBYTES

const crypto_box_PUBLICKEYBYTES = crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES

const crypto_box_SECRETKEYBYTES = crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES

const crypto_box_NONCEBYTES = crypto_box_curve25519xsalsa20poly1305_NONCEBYTES

const crypto_box_MACBYTES = crypto_box_curve25519xsalsa20poly1305_MACBYTES

const crypto_box_MESSAGEBYTES_MAX = crypto_box_curve25519xsalsa20poly1305_MESSAGEBYTES_MAX

const crypto_box_PRIMITIVE = "curve25519xsalsa20poly1305"

const crypto_box_BEFORENMBYTES = crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES

const crypto_box_SEALBYTES = crypto_box_PUBLICKEYBYTES + crypto_box_MACBYTES

const crypto_box_ZEROBYTES = crypto_box_curve25519xsalsa20poly1305_ZEROBYTES

const crypto_box_BOXZEROBYTES = crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES

const crypto_core_hsalsa20_OUTPUTBYTES = Cuint(32)

const crypto_core_hsalsa20_INPUTBYTES = Cuint(16)

const crypto_core_hsalsa20_KEYBYTES = Cuint(32)

const crypto_core_hsalsa20_CONSTBYTES = Cuint(16)

const crypto_core_hchacha20_OUTPUTBYTES = Cuint(32)

const crypto_core_hchacha20_INPUTBYTES = Cuint(16)

const crypto_core_hchacha20_KEYBYTES = Cuint(32)

const crypto_core_hchacha20_CONSTBYTES = Cuint(16)

const crypto_core_salsa20_OUTPUTBYTES = Cuint(64)

const crypto_core_salsa20_INPUTBYTES = Cuint(16)

const crypto_core_salsa20_KEYBYTES = Cuint(32)

const crypto_core_salsa20_CONSTBYTES = Cuint(16)

const crypto_core_salsa2012_OUTPUTBYTES = Cuint(64)

const crypto_core_salsa2012_INPUTBYTES = Cuint(16)

const crypto_core_salsa2012_KEYBYTES = Cuint(32)

const crypto_core_salsa2012_CONSTBYTES = Cuint(16)

const crypto_core_salsa208_OUTPUTBYTES = Cuint(64)

const crypto_core_salsa208_INPUTBYTES = Cuint(16)

const crypto_core_salsa208_KEYBYTES = Cuint(32)

const crypto_core_salsa208_CONSTBYTES = Cuint(16)

const crypto_generichash_blake2b_BYTES_MIN = Cuint(16)

const crypto_generichash_blake2b_BYTES_MAX = Cuint(64)

const crypto_generichash_blake2b_BYTES = Cuint(32)

const crypto_generichash_blake2b_KEYBYTES_MIN = Cuint(16)

const crypto_generichash_blake2b_KEYBYTES_MAX = Cuint(64)

const crypto_generichash_blake2b_KEYBYTES = Cuint(32)

const crypto_generichash_blake2b_SALTBYTES = Cuint(16)

const crypto_generichash_blake2b_PERSONALBYTES = Cuint(16)

const crypto_generichash_BYTES_MIN = crypto_generichash_blake2b_BYTES_MIN

const crypto_generichash_BYTES_MAX = crypto_generichash_blake2b_BYTES_MAX

const crypto_generichash_BYTES = crypto_generichash_blake2b_BYTES

const crypto_generichash_KEYBYTES_MIN = crypto_generichash_blake2b_KEYBYTES_MIN

const crypto_generichash_KEYBYTES_MAX = crypto_generichash_blake2b_KEYBYTES_MAX

const crypto_generichash_KEYBYTES = crypto_generichash_blake2b_KEYBYTES

const crypto_generichash_PRIMITIVE = "blake2b"

const crypto_hash_BYTES = crypto_hash_sha512_BYTES

const crypto_hash_PRIMITIVE = "sha512"

const crypto_kdf_blake2b_BYTES_MIN = 16

const crypto_kdf_blake2b_BYTES_MAX = 64

const crypto_kdf_blake2b_CONTEXTBYTES = 8

const crypto_kdf_blake2b_KEYBYTES = 32

const crypto_kdf_BYTES_MIN = crypto_kdf_blake2b_BYTES_MIN

const crypto_kdf_BYTES_MAX = crypto_kdf_blake2b_BYTES_MAX

const crypto_kdf_CONTEXTBYTES = crypto_kdf_blake2b_CONTEXTBYTES

const crypto_kdf_KEYBYTES = crypto_kdf_blake2b_KEYBYTES

const crypto_kdf_PRIMITIVE = "blake2b"

const crypto_kx_PUBLICKEYBYTES = 32

const crypto_kx_SECRETKEYBYTES = 32

const crypto_kx_SEEDBYTES = 32

const crypto_kx_SESSIONKEYBYTES = 32

const crypto_kx_PRIMITIVE = "x25519blake2b"

const crypto_onetimeauth_poly1305_BYTES = Cuint(16)

const crypto_onetimeauth_poly1305_KEYBYTES = Cuint(32)

const crypto_onetimeauth_BYTES = crypto_onetimeauth_poly1305_BYTES

const crypto_onetimeauth_KEYBYTES = crypto_onetimeauth_poly1305_KEYBYTES

const crypto_onetimeauth_PRIMITIVE = "poly1305"

const crypto_pwhash_argon2i_ALG_ARGON2I13 = 1

const crypto_pwhash_argon2i_BYTES_MIN = Cuint(16)

const crypto_pwhash_argon2i_BYTES_MAX = SODIUM_MIN(SODIUM_SIZE_MAX, Cuint(4294967295))

const crypto_pwhash_argon2i_PASSWD_MIN = Cuint(0)

const crypto_pwhash_argon2i_PASSWD_MAX = Cuint(4294967295)

const crypto_pwhash_argon2i_SALTBYTES = Cuint(16)

const crypto_pwhash_argon2i_STRBYTES = Cuint(128)

const crypto_pwhash_argon2i_STRPREFIX = "\$argon2i\$"

const crypto_pwhash_argon2i_OPSLIMIT_MIN = Cuint(3)

const crypto_pwhash_argon2i_OPSLIMIT_MAX = Cuint(4294967295)

const crypto_pwhash_argon2i_MEMLIMIT_MIN = Cuint(8192)

const crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE = Cuint(4)

const crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE = Cuint(33554432)

const crypto_pwhash_argon2i_OPSLIMIT_MODERATE = Cuint(6)

const crypto_pwhash_argon2i_MEMLIMIT_MODERATE = Cuint(134217728)

const crypto_pwhash_argon2i_OPSLIMIT_SENSITIVE = Cuint(8)

const crypto_pwhash_argon2i_MEMLIMIT_SENSITIVE = Cuint(536870912)

const crypto_pwhash_argon2id_ALG_ARGON2ID13 = 2

const crypto_pwhash_argon2id_BYTES_MIN = Cuint(16)

const crypto_pwhash_argon2id_BYTES_MAX = SODIUM_MIN(SODIUM_SIZE_MAX, Cuint(4294967295))

const crypto_pwhash_argon2id_PASSWD_MIN = Cuint(0)

const crypto_pwhash_argon2id_PASSWD_MAX = Cuint(4294967295)

const crypto_pwhash_argon2id_SALTBYTES = Cuint(16)

const crypto_pwhash_argon2id_STRBYTES = Cuint(128)

const crypto_pwhash_argon2id_STRPREFIX = "\$argon2id\$"

const crypto_pwhash_argon2id_OPSLIMIT_MIN = Cuint(1)

const crypto_pwhash_argon2id_OPSLIMIT_MAX = Cuint(4294967295)

const crypto_pwhash_argon2id_MEMLIMIT_MIN = Cuint(8192)

const crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE = Cuint(2)

const crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE = Cuint(67108864)

const crypto_pwhash_argon2id_OPSLIMIT_MODERATE = Cuint(3)

const crypto_pwhash_argon2id_MEMLIMIT_MODERATE = Cuint(268435456)

const crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE = Cuint(4)

const crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE = Cuint(1073741824)

const crypto_pwhash_ALG_ARGON2I13 = crypto_pwhash_argon2i_ALG_ARGON2I13

const crypto_pwhash_ALG_ARGON2ID13 = crypto_pwhash_argon2id_ALG_ARGON2ID13

const crypto_pwhash_ALG_DEFAULT = crypto_pwhash_ALG_ARGON2ID13

const crypto_pwhash_BYTES_MIN = crypto_pwhash_argon2id_BYTES_MIN

const crypto_pwhash_BYTES_MAX = crypto_pwhash_argon2id_BYTES_MAX

const crypto_pwhash_PASSWD_MIN = crypto_pwhash_argon2id_PASSWD_MIN

const crypto_pwhash_PASSWD_MAX = crypto_pwhash_argon2id_PASSWD_MAX

const crypto_pwhash_SALTBYTES = crypto_pwhash_argon2id_SALTBYTES

const crypto_pwhash_STRBYTES = crypto_pwhash_argon2id_STRBYTES

const crypto_pwhash_STRPREFIX = crypto_pwhash_argon2id_STRPREFIX

const crypto_pwhash_OPSLIMIT_MIN = crypto_pwhash_argon2id_OPSLIMIT_MIN

const crypto_pwhash_OPSLIMIT_MAX = crypto_pwhash_argon2id_OPSLIMIT_MAX

const crypto_pwhash_MEMLIMIT_MIN = crypto_pwhash_argon2id_MEMLIMIT_MIN

const crypto_pwhash_MEMLIMIT_MAX = crypto_pwhash_argon2id_MEMLIMIT_MAX

const crypto_pwhash_OPSLIMIT_INTERACTIVE = crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE

const crypto_pwhash_MEMLIMIT_INTERACTIVE = crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE

const crypto_pwhash_OPSLIMIT_MODERATE = crypto_pwhash_argon2id_OPSLIMIT_MODERATE

const crypto_pwhash_MEMLIMIT_MODERATE = crypto_pwhash_argon2id_MEMLIMIT_MODERATE

const crypto_pwhash_OPSLIMIT_SENSITIVE = crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE

const crypto_pwhash_MEMLIMIT_SENSITIVE = crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE

const crypto_pwhash_PRIMITIVE = "argon2i"

const crypto_scalarmult_curve25519_BYTES = Cuint(32)

const crypto_scalarmult_curve25519_SCALARBYTES = Cuint(32)

const crypto_scalarmult_BYTES = crypto_scalarmult_curve25519_BYTES

const crypto_scalarmult_SCALARBYTES = crypto_scalarmult_curve25519_SCALARBYTES

const crypto_scalarmult_PRIMITIVE = "curve25519"

const crypto_secretbox_xsalsa20poly1305_KEYBYTES = Cuint(32)

const crypto_secretbox_xsalsa20poly1305_NONCEBYTES = Cuint(24)

const crypto_secretbox_xsalsa20poly1305_MACBYTES = Cuint(16)

const crypto_secretbox_xsalsa20poly1305_MESSAGEBYTES_MAX = crypto_stream_xsalsa20_MESSAGEBYTES_MAX - crypto_secretbox_xsalsa20poly1305_MACBYTES

const crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES = Cuint(16)

const crypto_secretbox_xsalsa20poly1305_ZEROBYTES = crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES + crypto_secretbox_xsalsa20poly1305_MACBYTES

const crypto_secretbox_KEYBYTES = crypto_secretbox_xsalsa20poly1305_KEYBYTES

const crypto_secretbox_NONCEBYTES = crypto_secretbox_xsalsa20poly1305_NONCEBYTES

const crypto_secretbox_MACBYTES = crypto_secretbox_xsalsa20poly1305_MACBYTES

const crypto_secretbox_PRIMITIVE = "xsalsa20poly1305"

const crypto_secretbox_MESSAGEBYTES_MAX = crypto_secretbox_xsalsa20poly1305_MESSAGEBYTES_MAX

const crypto_secretbox_ZEROBYTES = crypto_secretbox_xsalsa20poly1305_ZEROBYTES

const crypto_secretbox_BOXZEROBYTES = crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES

const crypto_stream_chacha20_KEYBYTES = Cuint(32)

const crypto_stream_chacha20_NONCEBYTES = Cuint(8)

const crypto_stream_chacha20_MESSAGEBYTES_MAX = SODIUM_SIZE_MAX

const crypto_stream_chacha20_ietf_KEYBYTES = Cuint(32)

const crypto_stream_chacha20_ietf_NONCEBYTES = Cuint(12)

const crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX = SODIUM_MIN(SODIUM_SIZE_MAX, Culonglong(64) * Culonglong(1) << 32)

const crypto_stream_chacha20_IETF_KEYBYTES = crypto_stream_chacha20_ietf_KEYBYTES

const crypto_stream_chacha20_IETF_NONCEBYTES = crypto_stream_chacha20_ietf_NONCEBYTES

const crypto_stream_chacha20_IETF_MESSAGEBYTES_MAX = crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX

const crypto_secretstream_xchacha20poly1305_ABYTES = Cuint(1) + crypto_aead_xchacha20poly1305_ietf_ABYTES

const crypto_secretstream_xchacha20poly1305_HEADERBYTES = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES

const crypto_secretstream_xchacha20poly1305_KEYBYTES = crypto_aead_xchacha20poly1305_ietf_KEYBYTES

const crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX = SODIUM_MIN(SODIUM_SIZE_MAX - crypto_secretstream_xchacha20poly1305_ABYTES, Culonglong(64) * (Culonglong(1) << 32 - Culonglong(2)))

const crypto_secretstream_xchacha20poly1305_TAG_MESSAGE = 0x00

const crypto_secretstream_xchacha20poly1305_TAG_PUSH = 0x01

const crypto_secretstream_xchacha20poly1305_TAG_REKEY = 0x02

const crypto_secretstream_xchacha20poly1305_TAG_FINAL = crypto_secretstream_xchacha20poly1305_TAG_PUSH | crypto_secretstream_xchacha20poly1305_TAG_REKEY

const crypto_shorthash_siphash24_BYTES = Cuint(8)

const crypto_shorthash_siphash24_KEYBYTES = Cuint(16)

const crypto_shorthash_siphashx24_BYTES = Cuint(16)

const crypto_shorthash_siphashx24_KEYBYTES = Cuint(16)

const crypto_shorthash_BYTES = crypto_shorthash_siphash24_BYTES

const crypto_shorthash_KEYBYTES = crypto_shorthash_siphash24_KEYBYTES

const crypto_shorthash_PRIMITIVE = "siphash24"

const crypto_sign_ed25519_BYTES = Cuint(64)

const crypto_sign_ed25519_SEEDBYTES = Cuint(32)

const crypto_sign_ed25519_PUBLICKEYBYTES = Cuint(32)

const crypto_sign_ed25519_SECRETKEYBYTES = Cuint(32) + Cuint(32)

const crypto_sign_ed25519_MESSAGEBYTES_MAX = SODIUM_SIZE_MAX - crypto_sign_ed25519_BYTES

const crypto_sign_BYTES = crypto_sign_ed25519_BYTES

const crypto_sign_SEEDBYTES = crypto_sign_ed25519_SEEDBYTES

const crypto_sign_PUBLICKEYBYTES = crypto_sign_ed25519_PUBLICKEYBYTES

const crypto_sign_SECRETKEYBYTES = crypto_sign_ed25519_SECRETKEYBYTES

const crypto_sign_MESSAGEBYTES_MAX = crypto_sign_ed25519_MESSAGEBYTES_MAX

const crypto_sign_PRIMITIVE = "ed25519"

const crypto_stream_KEYBYTES = crypto_stream_xsalsa20_KEYBYTES

const crypto_stream_NONCEBYTES = crypto_stream_xsalsa20_NONCEBYTES

const crypto_stream_MESSAGEBYTES_MAX = crypto_stream_xsalsa20_MESSAGEBYTES_MAX

const crypto_stream_PRIMITIVE = "xsalsa20"

const crypto_stream_salsa20_KEYBYTES = Cuint(32)

const crypto_stream_salsa20_NONCEBYTES = Cuint(8)

const crypto_stream_salsa20_MESSAGEBYTES_MAX = SODIUM_SIZE_MAX

const crypto_verify_16_BYTES = Cuint(16)

const crypto_verify_32_BYTES = Cuint(32)

const crypto_verify_64_BYTES = Cuint(64)

const randombytes_BYTES_MAX = SODIUM_MIN(SODIUM_SIZE_MAX, Culong(0xffffffff))

const randombytes_SEEDBYTES = Cuint(32)

const sodium_base64_VARIANT_ORIGINAL = 1

const sodium_base64_VARIANT_ORIGINAL_NO_PADDING = 3

const sodium_base64_VARIANT_URLSAFE = 5

const sodium_base64_VARIANT_URLSAFE_NO_PADDING = 7

const crypto_stream_xchacha20_KEYBYTES = Cuint(32)

const crypto_stream_xchacha20_NONCEBYTES = Cuint(24)

const crypto_stream_xchacha20_MESSAGEBYTES_MAX = SODIUM_SIZE_MAX

const crypto_box_curve25519xchacha20poly1305_SEEDBYTES = Cuint(32)

const crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES = Cuint(32)

const crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES = Cuint(32)

const crypto_box_curve25519xchacha20poly1305_BEFORENMBYTES = Cuint(32)

const crypto_box_curve25519xchacha20poly1305_NONCEBYTES = Cuint(24)

const crypto_box_curve25519xchacha20poly1305_MACBYTES = Cuint(16)

const crypto_box_curve25519xchacha20poly1305_MESSAGEBYTES_MAX = crypto_stream_xchacha20_MESSAGEBYTES_MAX - crypto_box_curve25519xchacha20poly1305_MACBYTES

const crypto_box_curve25519xchacha20poly1305_SEALBYTES = crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES + crypto_box_curve25519xchacha20poly1305_MACBYTES

const crypto_core_ed25519_BYTES = 32

const crypto_core_ed25519_UNIFORMBYTES = 32

const crypto_core_ed25519_HASHBYTES = 64

const crypto_core_ed25519_SCALARBYTES = 32

const crypto_core_ed25519_NONREDUCEDSCALARBYTES = 64

const crypto_core_ristretto255_BYTES = 32

const crypto_core_ristretto255_HASHBYTES = 64

const crypto_core_ristretto255_SCALARBYTES = 32

const crypto_core_ristretto255_NONREDUCEDSCALARBYTES = 64

const crypto_scalarmult_ed25519_BYTES = Cuint(32)

const crypto_scalarmult_ed25519_SCALARBYTES = Cuint(32)

const crypto_scalarmult_ristretto255_BYTES = Cuint(32)

const crypto_scalarmult_ristretto255_SCALARBYTES = Cuint(32)

const crypto_secretbox_xchacha20poly1305_KEYBYTES = Cuint(32)

const crypto_secretbox_xchacha20poly1305_NONCEBYTES = Cuint(24)

const crypto_secretbox_xchacha20poly1305_MACBYTES = Cuint(16)

const crypto_secretbox_xchacha20poly1305_MESSAGEBYTES_MAX = crypto_stream_xchacha20_MESSAGEBYTES_MAX - crypto_secretbox_xchacha20poly1305_MACBYTES

const crypto_pwhash_scryptsalsa208sha256_BYTES_MIN = Cuint(16)

const crypto_pwhash_scryptsalsa208sha256_BYTES_MAX = SODIUM_MIN(SODIUM_SIZE_MAX, Culonglong(0x0000001fffffffe0))

const crypto_pwhash_scryptsalsa208sha256_PASSWD_MIN = Cuint(0)

const crypto_pwhash_scryptsalsa208sha256_PASSWD_MAX = SODIUM_SIZE_MAX

const crypto_pwhash_scryptsalsa208sha256_SALTBYTES = Cuint(32)

const crypto_pwhash_scryptsalsa208sha256_STRBYTES = Cuint(102)

const crypto_pwhash_scryptsalsa208sha256_STRPREFIX = "\$7\$"

const crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN = Cuint(32768)

const crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX = Cuint(4294967295)

const crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN = Cuint(16777216)

const crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX = SODIUM_MIN(SIZE_MAX, Culonglong(68719476736))

const crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE = Cuint(524288)

const crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE = Cuint(16777216)

const crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE = Cuint(33554432)

const crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE = Cuint(1073741824)

const crypto_stream_salsa2012_KEYBYTES = Cuint(32)

const crypto_stream_salsa2012_NONCEBYTES = Cuint(8)

const crypto_stream_salsa2012_MESSAGEBYTES_MAX = SODIUM_SIZE_MAX

const crypto_stream_salsa208_KEYBYTES = Cuint(32)

const crypto_stream_salsa208_NONCEBYTES = Cuint(8)

const crypto_stream_salsa208_MESSAGEBYTES_MAX = SODIUM_SIZE_MAX

# FIXME: handle extern
const randombytes_internal_implementation = randombytes_implementation
const randombytes_salsa20_implementation = randombytes_internal_implementation


# exports
const PREFIXES = ["SODIUM_", "sodium_", "crypto_", "randombytes_"]
for name in names(@__MODULE__; all=true), prefix in PREFIXES
    if startswith(string(name), prefix)
        @eval export $name
    end
end

end # module
