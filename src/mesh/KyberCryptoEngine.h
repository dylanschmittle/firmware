#pragma once
#include "CryptoEngine.h"
#include "kyber/common/params.h"
#include "kyber/kem/kem.h"
#include "kyber/fips202/fips202.h"
#include "kyber_protocol.h"

/**
 * Quantum-resistant crypto engine using CRYSTALS-KYBER KEM
 * Replaces Curve25519 with post-quantum key encapsulation
 * 
 * IMPORTANT: This implementation uses full Kyber key sizes:
 * - Public keys:  800 bytes (vs 32 for Curve25519)
 * - Private keys: 1632 bytes (vs 32 for Curve25519)  
 * - Ciphertext:   768 bytes (new requirement)
 * 
 * WARNING: Current Meshtastic protocol is incompatible with these sizes.
 * This implementation preserves quantum security but breaks network compatibility.
 */
class KyberCryptoEngine : public CryptoEngine
{
  public:
    KyberCryptoEngine();
    virtual ~KyberCryptoEngine();

#if !(MESHTASTIC_EXCLUDE_PKI)
#if !(MESHTASTIC_EXCLUDE_PKI_KEYGEN)
    virtual void generateKeyPair(uint8_t *pubKey, uint8_t *privKey) override;
    virtual bool regeneratePublicKey(uint8_t *pubKey, uint8_t *privKey) override;
#endif
    virtual bool encryptCurve25519(uint32_t toNode, uint32_t fromNode, meshtastic_UserLite_public_key_t remotePublic,
                                   uint64_t packetNum, size_t numBytes, const uint8_t *bytes, uint8_t *bytesOut) override;
    virtual bool decryptCurve25519(uint32_t fromNode, meshtastic_UserLite_public_key_t remotePublic, uint64_t packetNum,
                                   size_t numBytes, const uint8_t *bytes, uint8_t *bytesOut) override;
    virtual bool setDHPublicKey(uint8_t *publicKey) override;
    virtual void hash(uint8_t *bytes, size_t numBytes) override;
    
    // Kyber-specific protocol methods
    bool initiateKyberKeyExchange(uint32_t toNode);
    bool handleKyberProtocolMessage(const kyber_protocol_message_t* msg, uint32_t fromNode);
    bool sendKyberPublicKey(uint32_t toNode);
    bool processKyberCiphertext(const uint8_t* ciphertext, uint32_t fromNode);
#endif

  private:
    // Kyber key storage - significantly larger than Curve25519
    uint8_t kyber_public_key[CRYPTO_PUBLICKEYBYTES];   // 800 bytes
    uint8_t kyber_private_key[CRYPTO_SECRETKEYBYTES];  // 1632 bytes  
    uint8_t kyber_shared_secret[CRYPTO_BYTES];         // 32 bytes
    
    bool kyber_keys_generated;
    
    // Session management for multi-part key exchange
    kyber_session_context_t* active_sessions[KYBER_MAX_CONCURRENT_SESSIONS];
    uint8_t session_count;
    
    // Internal protocol methods
    kyber_session_context_t* findOrCreateSession(uint32_t peer_node);
    void cleanupExpiredSessions();
    bool sendKyberMessage(const kyber_protocol_message_t* msg, uint32_t toNode);
    
    // Utility functions for key size compatibility
    static constexpr size_t getPublicKeySize() { return CRYPTO_PUBLICKEYBYTES; }
    static constexpr size_t getPrivateKeySize() { return CRYPTO_SECRETKEYBYTES; }
    static constexpr size_t getCiphertextSize() { return CRYPTO_CIPHERTEXTBYTES; }
    static constexpr size_t getSharedSecretSize() { return CRYPTO_BYTES; }
};