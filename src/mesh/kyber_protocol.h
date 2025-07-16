/**
 * Protocol extensions for CRYSTALS-Kyber quantum-resistant cryptography
 * 
 * This header defines new message structures and protocols needed to support
 * Kyber's large key sizes within Meshtastic's LoRa packet constraints.
 * 
 * Key Constraints:
 * - LoRa max payload: 255 bytes
 * - Kyber public key: 800 bytes (needs chunking)
 * - Kyber ciphertext: 768 bytes (needs chunking) 
 * - Existing 32-byte key limit (backward compatibility)
 */

#pragma once

#include "kyber/common/params.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Use Kyber constants if CRYPTO_* not defined
#ifndef CRYPTO_PUBLICKEYBYTES
#define CRYPTO_PUBLICKEYBYTES KYBER_PUBLICKEYBYTES
#endif
#ifndef CRYPTO_SECRETKEYBYTES  
#define CRYPTO_SECRETKEYBYTES KYBER_SECRETKEYBYTES
#endif
#ifndef CRYPTO_CIPHERTEXTBYTES
#define CRYPTO_CIPHERTEXTBYTES KYBER_CIPHERTEXTBYTES  
#endif
#ifndef CRYPTO_BYTES
#define CRYPTO_BYTES KYBER_SSBYTES
#endif

// Protocol version for Kyber extensions
#define KYBER_PROTOCOL_VERSION 1

// Maximum chunk size for multi-part transmission
#define KYBER_CHUNK_SIZE 200  // Leave room for headers and metadata

// Calculate number of chunks needed for Kyber data
#define KYBER_PUBKEY_CHUNKS ((CRYPTO_PUBLICKEYBYTES + KYBER_CHUNK_SIZE - 1) / KYBER_CHUNK_SIZE)
#define KYBER_CIPHERTEXT_CHUNKS ((CRYPTO_CIPHERTEXTBYTES + KYBER_CHUNK_SIZE - 1) / KYBER_CHUNK_SIZE)

/**
 * Message types for Kyber protocol extensions
 */
typedef enum {
    KYBER_MSG_KEY_EXCHANGE_REQUEST = 1,   // Request to exchange Kyber public keys
    KYBER_MSG_KEY_CHUNK = 2,              // Chunk of public key data
    KYBER_MSG_KEY_CHUNK_ACK = 3,          // Acknowledgment of key chunk
    KYBER_MSG_CIPHERTEXT_CHUNK = 4,       // Chunk of KEM ciphertext
    KYBER_MSG_CIPHERTEXT_CHUNK_ACK = 5,   // Acknowledgment of ciphertext chunk
    KYBER_MSG_SESSION_ESTABLISHED = 6,    // Kyber session successfully established
    KYBER_MSG_ERROR = 7                   // Error in Kyber protocol
} kyber_message_type_t;

/**
 * Error codes for Kyber protocol
 */
typedef enum {
    KYBER_ERROR_NONE = 0,
    KYBER_ERROR_UNSUPPORTED = 1,          // Node doesn't support Kyber
    KYBER_ERROR_CHUNK_TIMEOUT = 2,        // Chunk transmission timeout
    KYBER_ERROR_ASSEMBLY_FAILED = 3,      // Failed to assemble chunks
    KYBER_ERROR_CRYPTO_FAILED = 4,        // Kyber crypto operation failed
    KYBER_ERROR_PROTOCOL_VERSION = 5      // Unsupported protocol version
} kyber_error_code_t;

/**
 * Kyber key exchange request message
 */
typedef struct {
    uint8_t protocol_version;             // Kyber protocol version
    uint32_t session_id;                  // Unique session identifier
    uint16_t pubkey_total_size;           // Total size of public key
    uint8_t total_chunks;                 // Total number of chunks expected
    bool supports_fallback;               // Can fallback to Curve25519
} kyber_key_exchange_request_t;

/**
 * Kyber data chunk message (for keys or ciphertext)
 */
typedef struct {
    uint32_t session_id;                  // Session identifier
    uint8_t chunk_index;                  // Index of this chunk (0-based)
    uint8_t total_chunks;                 // Total number of chunks
    uint16_t chunk_size;                  // Size of data in this chunk
    uint8_t data[KYBER_CHUNK_SIZE];       // Chunk data
    uint32_t checksum;                    // CRC32 of this chunk
} kyber_data_chunk_t;

/**
 * Kyber chunk acknowledgment
 */
typedef struct {
    uint32_t session_id;                  // Session identifier
    uint8_t chunk_index;                  // Index of acknowledged chunk
    bool success;                         // Whether chunk was received correctly
    kyber_error_code_t error_code;        // Error code if success=false
} kyber_chunk_ack_t;

/**
 * Kyber session established message
 */
typedef struct {
    uint32_t session_id;                  // Session identifier
    bool quantum_security;               // True if full Kyber security achieved
    uint8_t shared_secret_hash[8];        // First 8 bytes of shared secret (for verification)
} kyber_session_established_t;

/**
 * Main Kyber protocol message wrapper
 */
typedef struct {
    kyber_message_type_t msg_type;        // Type of Kyber message
    union {
        kyber_key_exchange_request_t key_request;
        kyber_data_chunk_t data_chunk;
        kyber_chunk_ack_t chunk_ack;
        kyber_session_established_t session_established;
        kyber_error_code_t error_code;
    } payload;
} kyber_protocol_message_t;

/**
 * State machine for Kyber key exchange
 */
typedef enum {
    KYBER_STATE_IDLE = 0,
    KYBER_STATE_REQUESTING,               // Sent key exchange request
    KYBER_STATE_SENDING_PUBKEY,           // Sending public key chunks
    KYBER_STATE_RECEIVING_PUBKEY,         // Receiving public key chunks
    KYBER_STATE_SENDING_CIPHERTEXT,       // Sending ciphertext chunks
    KYBER_STATE_RECEIVING_CIPHERTEXT,     // Receiving ciphertext chunks
    KYBER_STATE_ESTABLISHED,              // Session established
    KYBER_STATE_ERROR                     // Error state
} kyber_session_state_t;

/**
 * Kyber session context for managing multi-part exchanges
 */
typedef struct {
    uint32_t session_id;                  // Unique session ID
    kyber_session_state_t state;          // Current state
    uint32_t peer_node;                   // Node ID of peer
    
    // Key assembly buffers
    uint8_t* assembled_pubkey;            // Dynamically allocated to avoid stack overflow
    uint8_t received_chunks_mask;         // Bitmask of received chunks
    uint8_t expected_chunks;              // Total chunks expected
    
    // Ciphertext assembly buffers  
    uint8_t* assembled_ciphertext;        // Dynamically allocated to avoid stack overflow
    uint8_t ciphertext_chunks_mask;       // Bitmask of received ciphertext chunks
    uint8_t expected_ciphertext_chunks;   // Total ciphertext chunks expected
    
    // Timing and retry
    uint32_t last_activity_ms;            // Last activity timestamp
    uint8_t retry_count;                  // Number of retries attempted
    
    // Crypto state
    bool has_local_keypair;               // Local Kyber keys generated
    bool has_remote_pubkey;               // Remote public key assembled
    bool has_shared_secret;               // Shared secret derived
    uint8_t shared_secret[CRYPTO_BYTES];  // Derived shared secret
} kyber_session_context_t;

// Protocol constants
#define KYBER_SESSION_TIMEOUT_MS (30 * 1000)  // 30 second timeout
#define KYBER_CHUNK_RETRY_LIMIT 3              // Max retries per chunk
#define KYBER_MAX_CONCURRENT_SESSIONS 4        // Max simultaneous sessions

/**
 * Function prototypes for Kyber protocol implementation
 */
#ifdef __cplusplus
extern "C" {
#endif

// Session management
kyber_session_context_t* kyber_session_create(uint32_t peer_node);
void kyber_session_destroy(kyber_session_context_t* session);
bool kyber_session_is_expired(kyber_session_context_t* session);

// Message serialization
size_t kyber_message_encode(const kyber_protocol_message_t* msg, uint8_t* buffer, size_t buffer_size);
bool kyber_message_decode(const uint8_t* buffer, size_t buffer_size, kyber_protocol_message_t* msg);

// Protocol state machine
bool kyber_process_message(kyber_session_context_t* session, const kyber_protocol_message_t* msg);
bool kyber_send_key_request(kyber_session_context_t* session);
bool kyber_send_key_chunk(kyber_session_context_t* session, uint8_t chunk_index);
bool kyber_send_ciphertext_chunk(kyber_session_context_t* session, uint8_t chunk_index);

// Key assembly
bool kyber_assemble_public_key(kyber_session_context_t* session);
bool kyber_assemble_ciphertext(kyber_session_context_t* session);

// Utility functions
uint32_t kyber_generate_session_id(void);
uint32_t kyber_calculate_crc32(const uint8_t* data, size_t length);
bool kyber_validate_chunk(const kyber_data_chunk_t* chunk);

#ifdef __cplusplus
}
#endif