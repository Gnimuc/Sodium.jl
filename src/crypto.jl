using Base64
# helper functions for crypto_
"""
    seal(message, publickey)

Takes a message of any type which has a proper sizeof (to get proper C references)
and a base64 encoded public key from the remote.
All remaining arguments to call `libsodium.crypto_box_seal` are inferred automatically
and the result is returned as a base64 encoded string.
"""
function seal(message, publickey)
    len = sizeof(message)
    ciphertext = Vector{Cuchar}(undef, crypto_box_SEALBYTES + len)
    binpublickey = base64decode(publickey)
    crypto_box_seal(ciphertext, message, len, binpublickey)
    return base64encode(ciphertext)
end
