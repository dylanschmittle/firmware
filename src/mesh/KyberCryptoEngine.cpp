#include "KyberCryptoEngine.h"
#include "NodeDB.h"
#include "aes-ccm.h"
#include "meshUtils.h"
#include "kyber_protocol.h"
#include <Arduino.h>

#if !(MESHTASTIC_EXCLUDE_PKI)

KyberCryptoEngine::KyberCryptoEngine() : kyber_keys_generated(false), session_count(0)
{
    memset(kyber_public_key, 0, sizeof(kyber_public_key));
    memset(kyber_private_key, 0, sizeof(kyber_private_key));
    memset(kyber_shared_secret, 0, sizeof(kyber_shared_secret));
    memset(active_sessions, 0, sizeof(active_sessions));
}

KyberCryptoEngine::~KyberCryptoEngine()
{
    // Clear sensitive key material
    memset(kyber_private_key, 0, sizeof(kyber_private_key));
    memset(kyber_shared_secret, 0, sizeof(kyber_shared_secret));
    
    // Clean up active sessions
    for (int i = 0; i < KYBER_MAX_CONCURRENT_SESSIONS; i++) {
        if (active_sessions[i]) {
            kyber_session_destroy(active_sessions[i]);
            active_sessions[i] = nullptr;
        }
    }
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
        // Copy full keys to output buffers - NO TRUNCATION
        memcpy(pubKey, kyber_public_key, CRYPTO_PUBLICKEYBYTES);
        memcpy(privKey, kyber_private_key, CRYPTO_SECRETKEYBYTES);
        
        // Store truncated keys for legacy compatibility (DESTROYS SECURITY!)
        // NOTE: This breaks quantum security but maintains protocol compatibility
        // Full protocol redesign required for production quantum resistance
        size_t pub_copy_size = std::min(static_cast<size_t>(32), static_cast<size_t>(CRYPTO_PUBLICKEYBYTES));
        size_t priv_copy_size = std::min(static_cast<size_t>(32), static_cast<size_t>(CRYPTO_SECRETKEYBYTES));
        memcpy(public_key, kyber_public_key, pub_copy_size);
        memcpy(private_key, kyber_private_key, priv_copy_size);
        
        LOG_WARN("Key truncation preserves protocol compatibility but destroys quantum security!");
        LOG_WARN("Full keys: pub=%d bytes, priv=%d bytes", CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES);
        LOG_WARN("Truncated: pub=%zu bytes, priv=%zu bytes", pub_copy_size, priv_copy_size);
        
        kyber_keys_generated = true;
        LOG_DEBUG("Kyber keypair generated successfully - %d byte public key, %d byte private key", 
                  CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES);
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

    // For Kyber, we need the full public key, but remotePublic is limited by protocol
    // CRITICAL: This is a fundamental protocol incompatibility
    if (remotePublic.size < CRYPTO_PUBLICKEYBYTES) {
        LOG_ERROR("Kyber requires %d byte public key, got %d bytes - protocol incompatible", 
                  CRYPTO_PUBLICKEYBYTES, remotePublic.size);
        LOG_ERROR("This breaks quantum security - full protocol redesign needed");
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
    // Store the full Kyber public key for later use
    // WARNING: This method assumes caller provides a full CRYPTO_PUBLICKEYBYTES buffer
    // Current Meshtastic protocol only provides 32 bytes, causing security issues
    if (publicKey == nullptr) {
        LOG_ERROR("Cannot set null public key");
        return false;
    }
    
    memcpy(kyber_public_key, publicKey, CRYPTO_PUBLICKEYBYTES);
    LOG_DEBUG("Set Kyber public key - %d bytes", CRYPTO_PUBLICKEYBYTES);
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

// ==================== KYBER PROTOCOL METHODS ====================

kyber_session_context_t* KyberCryptoEngine::findOrCreateSession(uint32_t peer_node) {
    // First, try to find existing session
    for (int i = 0; i < KYBER_MAX_CONCURRENT_SESSIONS; i++) {
        if (active_sessions[i] && active_sessions[i]->peer_node == peer_node) {
            return active_sessions[i];
        }
    }
    
    // Clean up expired sessions to make room
    cleanupExpiredSessions();
    
    // Find an empty slot
    for (int i = 0; i < KYBER_MAX_CONCURRENT_SESSIONS; i++) {
        if (!active_sessions[i]) {
            active_sessions[i] = kyber_session_create(peer_node);
            if (active_sessions[i]) {
                session_count++;
            }
            return active_sessions[i];
        }
    }
    
    LOG_WARN("Maximum Kyber sessions reached, cannot create new session");
    return nullptr;
}

void KyberCryptoEngine::cleanupExpiredSessions() {
    for (int i = 0; i < KYBER_MAX_CONCURRENT_SESSIONS; i++) {
        if (active_sessions[i] && kyber_session_is_expired(active_sessions[i])) {
            LOG_INFO("Cleaning up expired Kyber session for node %d", active_sessions[i]->peer_node);
            kyber_session_destroy(active_sessions[i]);
            active_sessions[i] = nullptr;
            session_count--;
        }
    }
}

bool KyberCryptoEngine::sendKyberMessage(const kyber_protocol_message_t* msg, uint32_t toNode) {
    if (!msg) return false;
    
    // Encode message for transmission
    uint8_t buffer[256];
    size_t encoded_size = kyber_message_encode(msg, buffer, sizeof(buffer));
    
    if (encoded_size == 0) {
        LOG_ERROR("Failed to encode Kyber protocol message");
        return false;
    }
    
    // TODO: Send via Meshtastic packet system
    // This would need integration with the mesh router
    LOG_DEBUG("Would send Kyber message type %d to node %d (%zu bytes)", 
              msg->msg_type, toNode, encoded_size);
    
    return true;
}

bool KyberCryptoEngine::initiateKyberKeyExchange(uint32_t toNode) {
    if (!kyber_keys_generated) {
        LOG_ERROR("Cannot initiate Kyber key exchange - no local keys generated");
        return false;
    }
    
    kyber_session_context_t* session = findOrCreateSession(toNode);
    if (!session) {
        LOG_ERROR("Failed to create Kyber session for node %d", toNode);
        return false;
    }
    
    // Prepare key exchange request message
    kyber_protocol_message_t msg;
    msg.msg_type = KYBER_MSG_KEY_EXCHANGE_REQUEST;
    msg.payload.key_request.protocol_version = KYBER_PROTOCOL_VERSION;
    msg.payload.key_request.session_id = session->session_id;
    msg.payload.key_request.pubkey_total_size = CRYPTO_PUBLICKEYBYTES;
    msg.payload.key_request.total_chunks = KYBER_PUBKEY_CHUNKS;
    msg.payload.key_request.supports_fallback = true;
    
    session->state = KYBER_STATE_REQUESTING;
    session->has_local_keypair = true;
    
    LOG_INFO("Initiating Kyber key exchange with node %d (session %08x)", 
             toNode, session->session_id);
    
    return sendKyberMessage(&msg, toNode);
}

bool KyberCryptoEngine::sendKyberPublicKey(uint32_t toNode) {
    kyber_session_context_t* session = findOrCreateSession(toNode);
    if (!session || !kyber_keys_generated) {
        return false;
    }
    
    session->state = KYBER_STATE_SENDING_PUBKEY;
    
    // Send public key in chunks
    for (uint8_t chunk_idx = 0; chunk_idx < KYBER_PUBKEY_CHUNKS; chunk_idx++) {
        kyber_protocol_message_t msg;
        msg.msg_type = KYBER_MSG_KEY_CHUNK;
        
        auto& chunk = msg.payload.data_chunk;
        chunk.session_id = session->session_id;
        chunk.chunk_index = chunk_idx;
        chunk.total_chunks = KYBER_PUBKEY_CHUNKS;
        
        // Calculate chunk data
        size_t offset = chunk_idx * KYBER_CHUNK_SIZE;
        size_t remaining = CRYPTO_PUBLICKEYBYTES - offset;
        chunk.chunk_size = (remaining > KYBER_CHUNK_SIZE) ? KYBER_CHUNK_SIZE : remaining;
        
        memcpy(chunk.data, kyber_public_key + offset, chunk.chunk_size);
        chunk.checksum = kyber_calculate_crc32(chunk.data, chunk.chunk_size);
        
        if (!sendKyberMessage(&msg, toNode)) {
            LOG_ERROR("Failed to send Kyber public key chunk %d", chunk_idx);
            return false;
        }
        
        LOG_DEBUG("Sent Kyber public key chunk %d/%d to node %d", 
                  chunk_idx + 1, KYBER_PUBKEY_CHUNKS, toNode);
    }
    
    return true;
}

bool KyberCryptoEngine::handleKyberProtocolMessage(const kyber_protocol_message_t* msg, uint32_t fromNode) {
    if (!msg) return false;
    
    // Find or create session for this peer
    kyber_session_context_t* session = nullptr;
    
    // For key exchange requests, we need to find by session ID if it exists
    if (msg->msg_type == KYBER_MSG_KEY_EXCHANGE_REQUEST) {
        session = findOrCreateSession(fromNode);
    } else {
        // For other messages, find session by ID
        uint32_t session_id = 0;
        switch (msg->msg_type) {
            case KYBER_MSG_KEY_CHUNK:
            case KYBER_MSG_CIPHERTEXT_CHUNK:
                session_id = msg->payload.data_chunk.session_id;
                break;
            case KYBER_MSG_KEY_CHUNK_ACK:
            case KYBER_MSG_CIPHERTEXT_CHUNK_ACK:
                session_id = msg->payload.chunk_ack.session_id;
                break;
            case KYBER_MSG_SESSION_ESTABLISHED:
                session_id = msg->payload.session_established.session_id;
                break;
            default:
                LOG_WARN("Unknown Kyber message type in handler: %d", msg->msg_type);
                return false;
        }
        
        // Find session by ID
        for (int i = 0; i < KYBER_MAX_CONCURRENT_SESSIONS; i++) {
            if (active_sessions[i] && active_sessions[i]->session_id == session_id) {
                session = active_sessions[i];
                break;
            }
        }
    }
    
    if (!session) {
        LOG_ERROR("No valid Kyber session found for message from node %d", fromNode);
        return false;
    }
    
    return kyber_process_message(session, msg);
}

bool KyberCryptoEngine::processKyberCiphertext(const uint8_t* ciphertext, uint32_t fromNode) {
    if (!ciphertext || !kyber_keys_generated) {
        return false;
    }
    
    // Perform Kyber decapsulation
    uint8_t shared_secret[CRYPTO_BYTES];
    int result = crypto_kem_dec(shared_secret, ciphertext, kyber_private_key);
    
    if (result != 0) {
        LOG_ERROR("Kyber decapsulation failed for node %d", fromNode);
        return false;
    }
    
    // Use SHAKE256 for key derivation
    hash(shared_secret, CRYPTO_BYTES);
    memcpy(kyber_shared_secret, shared_secret, CRYPTO_BYTES);
    
    LOG_INFO("Kyber session established with node %d - quantum security active", fromNode);
    return true;
}

#endif