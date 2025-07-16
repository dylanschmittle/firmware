/**
 * Implementation of CRYSTALS-Kyber protocol extensions for Meshtastic
 * 
 * This implements the chunked transmission protocol needed to send Kyber's
 * large keys and ciphertext over LoRa's 255-byte packet size limit.
 */

#include "kyber_protocol.h"
#include "configuration.h"
#include <Arduino.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// Simple CRC32 implementation for chunk validation
static const uint32_t crc32_table[256] = {
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
    0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
    0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
    0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
    0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
    0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
    0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
    0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
    0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
    0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
    0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
    0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
    0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
    0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
    0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
    0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
    0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
    0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
    0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
    0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
    0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
    0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
    0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
    0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
    0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
    0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
    0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
    0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
    0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
    0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
    0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

uint32_t kyber_calculate_crc32(const uint8_t* data, size_t length) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; i++) {
        crc = crc32_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFF;
}

uint32_t kyber_generate_session_id(void) {
    // Generate a pseudo-random session ID using available entropy
    static uint32_t counter = 0;
    uint32_t timestamp = millis();
    uint32_t random_val = esp_random();
    return (timestamp ^ random_val ^ (++counter));
}

kyber_session_context_t* kyber_session_create(uint32_t peer_node) {
    kyber_session_context_t* session = (kyber_session_context_t*)calloc(1, sizeof(kyber_session_context_t));
    if (!session) {
        return nullptr;
    }
    
    // Allocate assembly buffers
    session->assembled_pubkey = (uint8_t*)malloc(CRYPTO_PUBLICKEYBYTES);
    session->assembled_ciphertext = (uint8_t*)malloc(CRYPTO_CIPHERTEXTBYTES);
    
    if (!session->assembled_pubkey || !session->assembled_ciphertext) {
        // Cleanup on allocation failure
        if (session->assembled_pubkey) free(session->assembled_pubkey);
        if (session->assembled_ciphertext) free(session->assembled_ciphertext);
        free(session);
        return nullptr;
    }
    
    // Initialize buffers
    memset(session->assembled_pubkey, 0, CRYPTO_PUBLICKEYBYTES);
    memset(session->assembled_ciphertext, 0, CRYPTO_CIPHERTEXTBYTES);
    
    session->session_id = kyber_generate_session_id();
    session->state = KYBER_STATE_IDLE;
    session->peer_node = peer_node;
    session->last_activity_ms = millis();
    session->retry_count = 0;
    session->received_chunks_mask = 0;
    session->ciphertext_chunks_mask = 0;
    session->has_local_keypair = false;
    session->has_remote_pubkey = false;
    session->has_shared_secret = false;
    
    return session;
}

void kyber_session_destroy(kyber_session_context_t* session) {
    if (session) {
        // Clear sensitive data
        memset(session->shared_secret, 0, sizeof(session->shared_secret));
        
        if (session->assembled_pubkey) {
            memset(session->assembled_pubkey, 0, CRYPTO_PUBLICKEYBYTES);
            free(session->assembled_pubkey);
        }
        
        if (session->assembled_ciphertext) {
            memset(session->assembled_ciphertext, 0, CRYPTO_CIPHERTEXTBYTES);
            free(session->assembled_ciphertext);
        }
        
        free(session);
    }
}

bool kyber_session_is_expired(kyber_session_context_t* session) {
    if (!session) return true;
    
    uint32_t current_time = millis();
    return (current_time - session->last_activity_ms) > KYBER_SESSION_TIMEOUT_MS;
}

bool kyber_validate_chunk(const kyber_data_chunk_t* chunk) {
    if (!chunk) return false;
    
    // Validate chunk parameters
    if (chunk->chunk_size > KYBER_CHUNK_SIZE) return false;
    if (chunk->chunk_index >= chunk->total_chunks) return false;
    
    // Validate checksum
    uint32_t calculated_crc = kyber_calculate_crc32(chunk->data, chunk->chunk_size);
    return calculated_crc == chunk->checksum;
}

size_t kyber_message_encode(const kyber_protocol_message_t* msg, uint8_t* buffer, size_t buffer_size) {
    if (!msg || !buffer || buffer_size < sizeof(kyber_protocol_message_t)) {
        return 0;
    }
    
    // Simple serialization - in production would use proper protobuf encoding
    size_t offset = 0;
    
    // Encode message type
    buffer[offset++] = (uint8_t)msg->msg_type;
    
    switch (msg->msg_type) {
        case KYBER_MSG_KEY_EXCHANGE_REQUEST:
            if (buffer_size < offset + sizeof(kyber_key_exchange_request_t)) return 0;
            memcpy(buffer + offset, &msg->payload.key_request, sizeof(kyber_key_exchange_request_t));
            offset += sizeof(kyber_key_exchange_request_t);
            break;
            
        case KYBER_MSG_KEY_CHUNK:
        case KYBER_MSG_CIPHERTEXT_CHUNK:
            if (buffer_size < offset + sizeof(kyber_data_chunk_t)) return 0;
            memcpy(buffer + offset, &msg->payload.data_chunk, sizeof(kyber_data_chunk_t));
            offset += sizeof(kyber_data_chunk_t);
            break;
            
        case KYBER_MSG_KEY_CHUNK_ACK:
        case KYBER_MSG_CIPHERTEXT_CHUNK_ACK:
            if (buffer_size < offset + sizeof(kyber_chunk_ack_t)) return 0;
            memcpy(buffer + offset, &msg->payload.chunk_ack, sizeof(kyber_chunk_ack_t));
            offset += sizeof(kyber_chunk_ack_t);
            break;
            
        case KYBER_MSG_SESSION_ESTABLISHED:
            if (buffer_size < offset + sizeof(kyber_session_established_t)) return 0;
            memcpy(buffer + offset, &msg->payload.session_established, sizeof(kyber_session_established_t));
            offset += sizeof(kyber_session_established_t);
            break;
            
        case KYBER_MSG_ERROR:
            if (buffer_size < offset + sizeof(kyber_error_code_t)) return 0;
            memcpy(buffer + offset, &msg->payload.error_code, sizeof(kyber_error_code_t));
            offset += sizeof(kyber_error_code_t);
            break;
            
        default:
            return 0;
    }
    
    return offset;
}

bool kyber_message_decode(const uint8_t* buffer, size_t buffer_size, kyber_protocol_message_t* msg) {
    if (!buffer || !msg || buffer_size < 1) {
        return false;
    }
    
    size_t offset = 0;
    
    // Decode message type
    msg->msg_type = (kyber_message_type_t)buffer[offset++];
    
    switch (msg->msg_type) {
        case KYBER_MSG_KEY_EXCHANGE_REQUEST:
            if (buffer_size < offset + sizeof(kyber_key_exchange_request_t)) return false;
            memcpy(&msg->payload.key_request, buffer + offset, sizeof(kyber_key_exchange_request_t));
            break;
            
        case KYBER_MSG_KEY_CHUNK:
        case KYBER_MSG_CIPHERTEXT_CHUNK:
            if (buffer_size < offset + sizeof(kyber_data_chunk_t)) return false;
            memcpy(&msg->payload.data_chunk, buffer + offset, sizeof(kyber_data_chunk_t));
            break;
            
        case KYBER_MSG_KEY_CHUNK_ACK:
        case KYBER_MSG_CIPHERTEXT_CHUNK_ACK:
            if (buffer_size < offset + sizeof(kyber_chunk_ack_t)) return false;
            memcpy(&msg->payload.chunk_ack, buffer + offset, sizeof(kyber_chunk_ack_t));
            break;
            
        case KYBER_MSG_SESSION_ESTABLISHED:
            if (buffer_size < offset + sizeof(kyber_session_established_t)) return false;
            memcpy(&msg->payload.session_established, buffer + offset, sizeof(kyber_session_established_t));
            break;
            
        case KYBER_MSG_ERROR:
            if (buffer_size < offset + sizeof(kyber_error_code_t)) return false;
            memcpy(&msg->payload.error_code, buffer + offset, sizeof(kyber_error_code_t));
            break;
            
        default:
            return false;
    }
    
    return true;
}

bool kyber_assemble_public_key(kyber_session_context_t* session) {
    if (!session) return false;
    
    // Check if all chunks have been received
    uint8_t expected_mask = (1 << session->expected_chunks) - 1;
    if (session->received_chunks_mask != expected_mask) {
        return false; // Still waiting for chunks
    }
    
    session->has_remote_pubkey = true;
    session->last_activity_ms = millis();
    
    LOG_INFO("Kyber public key assembled successfully (%d bytes)", CRYPTO_PUBLICKEYBYTES);
    return true;
}

bool kyber_assemble_ciphertext(kyber_session_context_t* session) {
    if (!session) return false;
    
    // Check if all ciphertext chunks have been received
    uint8_t expected_mask = (1 << session->expected_ciphertext_chunks) - 1;
    if (session->ciphertext_chunks_mask != expected_mask) {
        return false; // Still waiting for chunks
    }
    
    session->last_activity_ms = millis();
    
    LOG_INFO("Kyber ciphertext assembled successfully (%d bytes)", CRYPTO_CIPHERTEXTBYTES);
    return true;
}

bool kyber_process_message(kyber_session_context_t* session, const kyber_protocol_message_t* msg) {
    if (!session || !msg) return false;
    
    session->last_activity_ms = millis();
    
    switch (msg->msg_type) {
        case KYBER_MSG_KEY_EXCHANGE_REQUEST: {
            const auto& req = msg->payload.key_request;
            if (req.protocol_version != KYBER_PROTOCOL_VERSION) {
                LOG_ERROR("Unsupported Kyber protocol version: %d", req.protocol_version);
                return false;
            }
            
            session->expected_chunks = req.total_chunks;
            session->state = KYBER_STATE_RECEIVING_PUBKEY;
            LOG_INFO("Kyber key exchange started, expecting %d chunks", req.total_chunks);
            return true;
        }
        
        case KYBER_MSG_KEY_CHUNK: {
            const auto& chunk = msg->payload.data_chunk;
            
            if (!kyber_validate_chunk(&chunk)) {
                LOG_ERROR("Invalid Kyber key chunk received");
                return false;
            }
            
            // Copy chunk data to assembly buffer
            size_t offset = chunk.chunk_index * KYBER_CHUNK_SIZE;
            if (offset + chunk.chunk_size <= CRYPTO_PUBLICKEYBYTES) {
                memcpy(session->assembled_pubkey + offset, chunk.data, chunk.chunk_size);
                session->received_chunks_mask |= (1 << chunk.chunk_index);
                
                LOG_DEBUG("Received Kyber key chunk %d/%d", chunk.chunk_index + 1, chunk.total_chunks);
                
                // Check if all chunks received
                if (session->received_chunks_mask == ((1 << chunk.total_chunks) - 1)) {
                    return kyber_assemble_public_key(session);
                }
            }
            return true;
        }
        
        case KYBER_MSG_CIPHERTEXT_CHUNK: {
            const auto& chunk = msg->payload.data_chunk;
            
            if (!kyber_validate_chunk(&chunk)) {
                LOG_ERROR("Invalid Kyber ciphertext chunk received");
                return false;
            }
            
            // Copy chunk data to ciphertext assembly buffer
            size_t offset = chunk.chunk_index * KYBER_CHUNK_SIZE;
            if (offset + chunk.chunk_size <= CRYPTO_CIPHERTEXTBYTES) {
                memcpy(session->assembled_ciphertext + offset, chunk.data, chunk.chunk_size);
                session->ciphertext_chunks_mask |= (1 << chunk.chunk_index);
                
                LOG_DEBUG("Received Kyber ciphertext chunk %d/%d", chunk.chunk_index + 1, chunk.total_chunks);
                
                // Check if all chunks received
                if (session->ciphertext_chunks_mask == ((1 << chunk.total_chunks) - 1)) {
                    return kyber_assemble_ciphertext(session);
                }
            }
            return true;
        }
        
        case KYBER_MSG_SESSION_ESTABLISHED: {
            const auto& established = msg->payload.session_established;
            session->state = KYBER_STATE_ESTABLISHED;
            LOG_INFO("Kyber session established with quantum security: %s", 
                     established.quantum_security ? "YES" : "NO");
            return true;
        }
        
        case KYBER_MSG_ERROR: {
            LOG_ERROR("Kyber protocol error: %d", msg->payload.error_code);
            session->state = KYBER_STATE_ERROR;
            return false;
        }
        
        default:
            LOG_WARN("Unknown Kyber message type: %d", msg->msg_type);
            return false;
    }
}