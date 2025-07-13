#pragma once

// Enable Kyber crypto engine instead of default Curve25519
#define USE_KYBER_CRYPTO 1

// Kyber configuration - matches ESP32 optimized settings
#ifndef KYBER_K
#define KYBER_K 2  // Kyber512 for reasonable performance on ESP32
#endif

#ifndef KYBER_90S
#define KYBER_90S  // Use 90s variant with AES/SHA instead of SHAKE
#endif

// Compatibility settings for Meshtastic protocol
#define KYBER_COMPAT_PUBLIC_KEY_SIZE 32   // Truncate for existing protocol
#define KYBER_COMPAT_PRIVATE_KEY_SIZE 32  // Truncate for existing protocol

// Performance settings for ESP32
#define KYBER_ESP32_OPTIMIZED 1