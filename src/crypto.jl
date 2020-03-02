# helper functions for crypto_
function LibSodium.crypto_box_seal(msg, pk)
    len = sizeof(msg)
    ciphertext = Vector{Cuchar}(undef, crypto_box_SEALBYTES + len)
    result = crypto_box_seal(ciphertext, msg, len, pk)
    result == 0 || error("failed to seal box!")
    return ciphertext
end
