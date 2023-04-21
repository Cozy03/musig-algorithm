import hashlib
import ecdsa

def musig_sign(private_keys, message):
    # Generate combined public key
    public_keys = [ecdsa.SigningKey.from_string(key, curve=ecdsa.SECP256k1).verifying_key.to_string() for key in private_keys]
    combined_public_key = hashlib.sha256(b''.join(public_keys)).digest()

    # Generate combined nonce
    nonces = [ecdsa.util.randrange(ecdsa.SECP256k1.order) for _ in private_keys]
    combined_nonce = ecdsa.util.point_multiply(ecdsa.SECP256k1.generator, nonces[0])
    for nonce in nonces[1:]:
        combined_nonce += ecdsa.util.point_multiply(ecdsa.SECP256k1.generator, nonce)
    combined_nonce = combined_nonce.x() % ecdsa.SECP256k1.order

    # Generate individual signatures
    individual_signatures = []
    for i in range(len(private_keys)):
        signing_key = ecdsa.SigningKey.from_string(private_keys[i], curve=ecdsa.SECP256k1)
        partial_nonce = ecdsa.util.point_multiply(combined_public_key, nonces[i])
        message_hash = hashlib.sha256(hashlib.sha256(message.encode('utf-8')).digest()).digest()
        partial_sig = signing_key.sign_digest(message_hash, sigencode=ecdsa.util.sigencode_der_canonize)
        individual_signatures.append((partial_nonce, partial_sig))

    # Generate combined signature
    r = combined_nonce
    s = 0
    for nonce, sig in individual_signatures:
        s += ecdsa.util.string_to_number(sig) * ecdsa.util.inv_mod(nonce, ecdsa.SECP256k1.order)
    s %= ecdsa.SECP256k1.order
    combined_sig = ecdsa.util.number_to_string(r, ecdsa.SECP256k1.order) + ecdsa.util.number_to_string(s, ecdsa.SECP256k1.order)

    return combined_sig

def musig_verify(public_keys, message, combined_sig):
    # Generate combined public key
    combined_public_key = hashlib.sha256(b''.join(public_keys)).digest()

    # Verify signature
    message_hash = hashlib.sha256(hashlib.sha256(message.encode('utf-8')).digest()).digest()
    combined_sig_obj = ecdsa.util.sigdecode_der(combined_sig, ecdsa.SECP256k1.generator.order())
    r = combined_sig_obj[0]
    s = combined_sig_obj[1]
    s_inv = ecdsa.util.inv_mod(s, ecdsa.SECP256k1.order)
    u1 = (ecdsa.util.string_to_number(message_hash) * s_inv) % ecdsa.SECP256k1.order
    u2 = (r * s_inv) % ecdsa.SECP256k1.order
    combined_nonce = ecdsa.util.number_to_point(u1, ecdsa.SECP256k1.generator) + ecdsa.util.number_to_point(u2, ecdsa.VerifyingKey.from_string(combined_public_key, curve=ecdsa.SECP256k1).pubkey.point)
    if combined_nonce.x() % ecdsa.SECP256k1.order == r:
        return True
    else:
        return False
