#pragma once
#include "CryptoEngine.h"
#include "kyber/common/params.h"
#include "kyber/kem/kem.h"
#include "kyber/fips202/fips202.h"

/**
 * Quantum-resistant crypto engine using CRYSTALS-KYBER KEM
 * Replaces Curve25519 with post-quantum key encapsulation
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
#endif

  private:
    // Kyber key storage - larger than Curve25519
    uint8_t kyber_public_key[CRYPTO_PUBLICKEYBYTES];
    uint8_t kyber_private_key[CRYPTO_SECRETKEYBYTES];
    uint8_t kyber_shared_secret[CRYPTO_BYTES];
    
    bool kyber_keys_generated;
};