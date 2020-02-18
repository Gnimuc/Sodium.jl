using Sodium.LibSodium
using Test

@testset "Sodium" begin
    @test sodium_init() ≥ 0
    @info "libsodium library version : " * unsafe_string(sodium_version_string())
end
