# helper functions for crypto_
function crypto_box_seal(msg, pk)
    len = sizeof(msg)
    ciphertext = Vector{Cuchar}(undef, crypto_box_SEALBYTES + len)
    crypto_box_seal(ciphertext, msg, len, pk)
    return String(ciphertext)
end
