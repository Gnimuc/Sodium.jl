using Sodium
using Sodium.LibSodium
using Test
using Base64

@testset "Sodium" begin
    @test sodium_init() ≥ 0
    @info "libsodium library version : " * unsafe_string(sodium_version_string())
end

@testset "Sealed boxes" begin
    msg = "Message"
    msg_len = length(msg)
    ciphertext_len = crypto_box_SEALBYTES + msg_len
    recipient_pk = Vector{Cuchar}(undef, crypto_box_PUBLICKEYBYTES)
    recipient_sk = Vector{Cuchar}(undef, crypto_box_SECRETKEYBYTES)
    @test crypto_box_keypair(recipient_pk, recipient_sk) == 0
    ciphertext = Vector{Cuchar}(undef, ciphertext_len)
    @test crypto_box_seal(ciphertext, msg, msg_len, recipient_pk) == 0
    decrypted = Vector{Cuchar}(undef, msg_len)
    @test crypto_box_seal_open(decrypted, ciphertext, ciphertext_len, recipient_pk, recipient_sk) == 0
    @test String(decrypted) == msg
end

@testset "Sealed boxes convenience" begin
    msg = "My Message with true Unicode öéâù"
    recipient_pk = Vector{Cuchar}(undef, crypto_box_PUBLICKEYBYTES)
    recipient_sk = Vector{Cuchar}(undef, crypto_box_SECRETKEYBYTES)
    @test crypto_box_keypair(recipient_pk, recipient_sk) == 0
    encrypted = seal(msg, base64encode(recipient_pk))
    ciphertext = base64decode(encrypted)
    decrypted = Vector{Cuchar}(undef, sizeof(ciphertext)-crypto_box_sealbytes())
    @test crypto_box_seal_open(decrypted, ciphertext, sizeof(ciphertext), recipient_pk, recipient_sk) == 0
    @test String(decrypted) == msg
end
