using Base64
# helper functions for crypto_
"""
    seal(message, publickey)

Takes a message of any type which has a proper sizeof (to get proper C references)
and a public key from the remote.
All remaining arguments to call `libsodium.crypto_box_seal` are inferred automatically
and the result is returned as a base64 encoded string.
"""
function seal(msg, pk)
    len = sizeof(msg)
    ciphertext = Vector{Cuchar}(undef, crypto_box_SEALBYTES + len)
    crypto_box_seal(ciphertext, msg, len, pk)
    return base64encode(ciphertext)
end
