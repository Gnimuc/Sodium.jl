using Base64
# helper functions for crypto_
export seal

preparepubkey(publickey::String) = base64decode(publickey)
preparepubkey(publickey::Vector{UInt8}) = publickey

"""
    seal(message::Base.SecretBuffer, publickey)

Takes a `SecretBuffer` holding a secret message and a base64 encoded public key from the remote.
All remaining arguments to call `libsodium.crypto_box_seal` are inferred automatically.
After that call, message is `shred!`ed and the result is returned as a base64 encoded string.
"""
function seal(message::Base.SecretBuffer, publickey)
    seekstart(message)
    len = bytesavailable(message)
    ciphertext = Vector{Cuchar}(undef, crypto_box_SEALBYTES + len)
    binpublickey = preparepubkey(publickey)
    crypto_box_seal(ciphertext, message.data, len, binpublickey)
    Base.shred!(message)
    return base64encode(ciphertext)
end

"""
    seal(message::Vector{UInt8}, publickey)

Convenience function which wraps the message in a `SecretBuffer` before calling
`seal(::SecretBuffer, publickey)`. Also wipes and empties the message vector.
"""
seal(message::Vector{UInt8}, publickey) = seal(Base.SecretBuffer!(message), publickey)

"""
    seal(message, publickey)

Fallback that creates a secret by `write(secretbuffer, message)`. Won't cleanup message object.
"""
function seal(message, publickey)
    @warn "You need to cleanup the message yourself"
    secret = Base.SecretBuffer()
    write(secret, message)
    seal(secret, publickey)
end