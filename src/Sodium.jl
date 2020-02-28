module Sodium

include("LibSodium.jl")
using .LibSodium

include("crypto.jl")
export crypto_box_seal

function __init__()
	sodium_init() ≥ 0 || error("libsodium failed to init.")
end

end # module
