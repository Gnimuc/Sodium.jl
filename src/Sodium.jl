module Sodium

include("LibSodium.jl")
using .LibSodium

function __init__()
	sodium_init() ≥ 0 || error("libsodium failed to init.")
end

end # module
