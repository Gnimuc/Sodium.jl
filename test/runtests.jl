using Sodium.LibSodium
using Test

@testset "Sodium" begin
    @test sodium_init() ≥ 0
    @info "libsodium library version : " * unsafe_string(sodium_version_string())
end

@testset "Sealed boxes" begin
    msg = "Message"
    msg_len = sizeof(msg)
    ciphertext_len = crypto_box_SEALBYTES + msg_len
    recipient_pk = Vector{Cuchar}(undef, crypto_box_PUBLICKEYBYTES)
    recipient_sk = Vector{Cuchar}(undef, crypto_box_SECRETKEYBYTES)
    @test crypto_box_keypair(recipient_pk, recipient_sk) == 0
    ciphertext = Vector{Cuchar}(undef, ciphertext_len)
    @test crypto_box_seal(ciphertext, msg, msg_len, recipient_pk) == 0
    @test crypto_box_seal(msg, recipient_pk) == ciphertext
    decrypted = Vector{Cuchar}(undef, msg_len)
    @test crypto_box_seal_open(decrypted, ciphertext, ciphertext_len, recipient_pk, recipient_sk) == 0
    @test String(decrypted) == msg
end
