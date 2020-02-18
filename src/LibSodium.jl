module LibSodium

using libsodium_jll
export libsodium_jll

# patches
const UINT64_MAX = typemax(UInt64)
const SIZE_MAX = typemax(UInt32)
SODIUM_MIN(A, B) = A < B ? A : B
const SODIUM_SIZE_MAX = SODIUM_MIN(UINT64_MAX, SIZE_MAX)

struct crypto_aead_aes256gcm_state_
    opaque::NTuple{512,Cuchar}
end

struct crypto_generichash_blake2b_state
    opaque::NTuple{384,Cuchar}
end

struct crypto_onetimeauth_poly1305_state
    opaque::NTuple{256,Cuchar}
end

const crypto_pwhash_argon2id_BYTES_MAX = SODIUM_MIN(SODIUM_SIZE_MAX, Cuint(4294967295))
const crypto_pwhash_argon2i_BYTES_MAX = SODIUM_MIN(SODIUM_SIZE_MAX, Cuint(4294967295) )
const crypto_pwhash_argon2i_MEMLIMIT_MAX = ( ( SIZE_MAX >= 4398046510080 ) ? 4398046510080 : ( SIZE_MAX >= Cuint(2147483648) ) ? Cuint(2147483648) : Cuint(32768) )
const crypto_pwhash_argon2id_MEMLIMIT_MAX = ( ( SIZE_MAX >= 4398046510080 ) ? 4398046510080 : ( SIZE_MAX >= Cuint(2147483648) ) ? Cuint(2147483648) : Cuint(32768) )

include(joinpath(@__DIR__, "..", "gen", "libsodium_common.jl"))
include(joinpath(@__DIR__, "..", "gen", "libsodium_api.jl"))

foreach(names(@__MODULE__, all=true)) do s
    if startswith(string(s), "SODIUM_") ||
       startswith(string(s), "sodium_") ||
       startswith(string(s), "crypto_") ||
       startswith(string(s), "randombytes_")
        @eval export $s
    end
end

end # module
