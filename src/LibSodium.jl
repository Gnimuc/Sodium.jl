module LibSodium

using libsodium_jll
export libsodium_jll

using CEnum

const Ctm = Base.Libc.TmStruct
const Ctime_t = UInt
const Cclock_t = UInt
export Ctm, Ctime_t, Cclock_t

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
