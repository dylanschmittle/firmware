#include "KyberCryptoEngine.h"
#include "NodeDB.h"
#include "aes-ccm.h"
#include "meshUtils.h"
#include <Arduino.h>

#if !(MESHTASTIC_EXCLUDE_PKI)

KyberCryptoEngine::KyberCryptoEngine() : kyber_keys_generated(false)
{
    memset(kyber_public_key, 0, sizeof(kyber_public_key));
    memset(kyber_private_key, 0, sizeof(kyber_private_key));
    memset(kyber_shared_secret, 0, sizeof(kyber_shared_secret));
}

KyberCryptoEngine::~KyberCryptoEngine()
{
    // Clear sensitive key material
    memset(kyber_private_key, 0, sizeof(kyber_private_key));
    memset(kyber_shared_secret, 0, sizeof(kyber_shared_secret));
}

#if !(MESHTASTIC_EXCLUDE_PKI_KEYGEN)
/**
 * Generate a Kyber public/private key pair
 * 
 * @param pubKey The destination for the public key (CRYPTO_PUBLICKEYBYTES)
 * @param privKey The destination for the private key (CRYPTO_SECRETKEYBYTES)
 */
void KyberCryptoEngine::generateKeyPair(uint8_t *pubKey, uint8_t *privKey)
{
    LOG_DEBUG("Generate Kyber keypair");
    
    // Generate Kyber key pair
    int result = crypto_kem_keypair(kyber_public_key, kyber_private_key);
    
    if (result == 0) {
        // Copy keys to output buffers
        memcpy(pubKey, kyber_public_key, CRYPTO_PUBLICKEYBYTES);
        memcpy(privKey, kyber_private_key, CRYPTO_SECRETKEYBYTES);
        
        // Store for later use - truncate for compatibility with existing 32-byte interface
        memcpy(public_key, kyber_public_key, 32);
        memcpy(private_key, kyber_private_key, 32);
        
        kyber_keys_generated = true;
        LOG_DEBUG("Kyber keypair generated successfully");
    } else {
        LOG_ERROR("Kyber keypair generation failed");
        kyber_keys_generated = false;
    }
}

/**
 * Regenerate public key from private key (for Kyber this requires full key pair generation)
 */
bool KyberCryptoEngine::regeneratePublicKey(uint8_t *pubKey, uint8_t *privKey)
{
    // For Kyber, we can't easily regenerate just the public key from private key
    // This would require a different approach - for now, generate new pair
    LOG_WARN("Kyber public key regeneration not supported - generating new keypair");
    generateKeyPair(pubKey, privKey);
    return kyber_keys_generated;
}
#endif

/**
 * Encrypt using Kyber KEM + AES-CCM
 * Replace Curve25519 ECDH with Kyber key encapsulation
 */
bool KyberCryptoEngine::encryptCurve25519(uint32_t toNode, uint32_t fromNode, meshtastic_UserLite_public_key_t remotePublic,
                                         uint64_t packetNum, size_t numBytes, const uint8_t *bytes, uint8_t *bytesOut)
{
    if (remotePublic.size == 0) {
        LOG_DEBUG("Node %d or their public_key not found", toNode);
        return false;
    }

    // For Kyber, we need the full public key, but remotePublic might be truncated
    // This is a compatibility issue that needs addressing in the protocol
    if (remotePublic.size < CRYPTO_PUBLICKEYBYTES) {
        LOG_ERROR("Kyber requires %d byte public key, got %d bytes", CRYPTO_PUBLICKEYBYTES, remotePublic.size);
        return false;
    }

    uint8_t ciphertext[CRYPTO_CIPHERTEXTBYTES];
    uint8_t shared_secret[CRYPTO_BYTES];
    
    // Perform Kyber encapsulation to generate shared secret
    int result = crypto_kem_enc(ciphertext, shared_secret, remotePublic.bytes);
    
    if (result != 0) {
        LOG_ERROR("Kyber encapsulation failed");
        return false;
    }

    // Use SHAKE256 for key derivation instead of SHA256
    hash(shared_secret, CRYPTO_BYTES);
    memcpy(kyber_shared_secret, shared_secret, CRYPTO_BYTES);

    uint8_t *auth;
    long extraNonceTmp = random();
    auth = bytesOut + numBytes;
    memcpy((uint8_t *)(auth + 8), &extraNonceTmp, sizeof(uint32_t));
    
    initNonce(fromNode, packetNum, extraNonceTmp);

    // Encrypt with AES-CCM using derived key
    printBytes("Kyber encrypt with nonce: ", nonce, 13);
    printBytes("Kyber encrypt with shared_secret: ", shared_secret, 8);
    
    aes_ccm_ae(shared_secret, 32, nonce, 8, bytes, numBytes, nullptr, 0, bytesOut, auth);
    memcpy((uint8_t *)(auth + 8), &extraNonceTmp, sizeof(uint32_t));
    
    // TODO: Store ciphertext for the recipient to decrypt the KEM
    // This requires protocol changes to transmit the Kyber ciphertext
    
    return true;
}

/**
 * Decrypt using Kyber KEM + AES-CCM
 */
bool KyberCryptoEngine::decryptCurve25519(uint32_t fromNode, meshtastic_UserLite_public_key_t remotePublic, uint64_t packetNum,
                                         size_t numBytes, const uint8_t *bytes, uint8_t *bytesOut)
{
    const uint8_t *auth = bytes + numBytes - 12;
    uint32_t extraNonce;
    memcpy(&extraNonce, auth + 8, sizeof(uint32_t));
    
    LOG_INFO("Kyber decrypt with nonce: %d", extraNonce);

    // TODO: Extract Kyber ciphertext from the message
    // For now, this is incomplete as it requires protocol changes
    uint8_t ciphertext[CRYPTO_CIPHERTEXTBYTES];
    uint8_t shared_secret[CRYPTO_BYTES];
    
    // Perform Kyber decapsulation
    int result = crypto_kem_dec(shared_secret, ciphertext, kyber_private_key);
    
    if (result != 0) {
        LOG_ERROR("Kyber decapsulation failed");
        return false;
    }

    // Use SHAKE256 for key derivation
    hash(shared_secret, CRYPTO_BYTES);
    
    initNonce(fromNode, packetNum, extraNonce);
    printBytes("Kyber decrypt with nonce: ", nonce, 13);
    printBytes("Kyber decrypt with shared_secret: ", shared_secret, 8);
    
    return aes_ccm_ad(shared_secret, 32, nonce, 8, bytes, numBytes - 12, nullptr, 0, auth, bytesOut);
}

bool KyberCryptoEngine::setDHPublicKey(uint8_t *publicKey)
{
    // Store the public key for later use
    // Note: This assumes publicKey is at least CRYPTO_PUBLICKEYBYTES
    memcpy(kyber_public_key, publicKey, CRYPTO_PUBLICKEYBYTES);
    return true;
}

/**
 * Hash using SHAKE256 instead of SHA256 for post-quantum security
 */
void KyberCryptoEngine::hash(uint8_t *bytes, size_t numBytes)
{
    // Use SHAKE256 from FIPS202 for variable-length output
    shake256(bytes, 32, bytes, numBytes);
}

#endif