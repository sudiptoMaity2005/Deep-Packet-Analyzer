#include "protocol/sni_extractor.h"
#include <cstring>
#include <algorithm>

namespace DPI {

// ============================================================================
// TLS SNI Extractor Implementation
// ============================================================================

uint16_t SNIExtractor::readUint16BE(const uint8_t* data) {
    return (static_cast<uint16_t>(data[0]) << 8) | data[1];
}

uint32_t SNIExtractor::readUint24BE(const uint8_t* data) {
    return (static_cast<uint32_t>(data[0]) << 16) |
           (static_cast<uint32_t>(data[1]) << 8) |
           data[2];
}

bool SNIExtractor::isTLSClientHello(const uint8_t* payload, size_t length) {
    // Minimum TLS record: 5 bytes header + 4 bytes handshake header
    if (length < 9) return false;
    
    // Check TLS record header
    // Byte 0: Content Type (should be 0x16 = Handshake)
    if (payload[0] != CONTENT_TYPE_HANDSHAKE) return false;
    
    // Bytes 1-2: TLS Version (0x0301 = TLS 1.0, 0x0303 = TLS 1.2)
    // We accept 0x0300 (SSL 3.0) through 0x0304 (TLS 1.3)
    uint16_t version = readUint16BE(payload + 1);
    if (version < 0x0300 || version > 0x0304) return false;
    
    // Bytes 3-4: Record length
    uint16_t record_length = readUint16BE(payload + 3);
    if (record_length > length - 5) return false;
    
    // Check handshake header (starts at byte 5)
    // Byte 5: Handshake Type (should be 0x01 = Client Hello)
    if (payload[5] != HANDSHAKE_CLIENT_HELLO) return false;
    
    return true;
}

std::optional<std::string> SNIExtractor::extractFromClientHello(const uint8_t* data, size_t length) {
    if (length < 38) return std::nullopt;
    if (data[0] != HANDSHAKE_CLIENT_HELLO) return std::nullopt;
    
    // Handshake header:
    // Byte 0: Handshake type (0x01 = Client Hello)
    // Bytes 1-3: Handshake length (24-bit integer)
    uint32_t handshake_length = readUint24BE(data + 1);
    if (handshake_length > length - 4) {
        handshake_length = static_cast<uint32_t>(length - 4);
    }
    
    // Client Hello body begins at offset 4:
    // Bytes 0-1: Client version (offset 4..5)
    // Bytes 2-33: Random 32 bytes (offset 6..37)
    // Byte 34: Session ID Length (offset 38)
    size_t offset = 38;
    if (offset >= length) return std::nullopt;
    uint8_t session_id_length = data[offset++];
    offset += session_id_length;
    
    // Cipher suites
    if (offset + 2 > length) return std::nullopt;
    uint16_t cipher_suites_length = readUint16BE(data + offset);
    offset += 2 + cipher_suites_length;
    
    // Compression methods
    if (offset >= length) return std::nullopt;
    uint8_t compression_methods_length = data[offset++];
    offset += compression_methods_length;
    
    // Extensions
    if (offset + 2 > length) return std::nullopt;
    uint16_t extensions_length = readUint16BE(data + offset);
    offset += 2;
    
    size_t extensions_end = std::min(offset + extensions_length, length);
    
    // Parse extensions to find SNI
    while (offset + 4 <= extensions_end) {
        uint16_t extension_type = readUint16BE(data + offset);
        uint16_t extension_length = readUint16BE(data + offset + 2);
        offset += 4;
        
        if (offset + extension_length > extensions_end) break;
        
        if (extension_type == EXTENSION_SNI) {
            if (extension_length < 5) break;
            
            uint16_t sni_list_length = readUint16BE(data + offset);
            if (sni_list_length < 3) break;
            
            uint8_t sni_type = data[offset + 2];
            uint16_t sni_length = readUint16BE(data + offset + 3);
            
            if (sni_type != SNI_TYPE_HOSTNAME) break;
            if (sni_length > extension_length - 5) break;
            
            // Extract the hostname
            return std::string(reinterpret_cast<const char*>(data + offset + 5), sni_length);
        }
        
        offset += extension_length;
    }
    
    return std::nullopt;
}

std::optional<std::string> SNIExtractor::extract(const uint8_t* payload, size_t length) {
    if (!isTLSClientHello(payload, length)) {
        return std::nullopt;
    }
    
    // Skip TLS record header (5 bytes) and parse the Handshake Client Hello
    return extractFromClientHello(payload + 5, length - 5);
}

std::vector<std::pair<uint16_t, std::string>> SNIExtractor::extractExtensions(
    const uint8_t* payload, size_t length) {
    (void)payload;
    (void)length;
    std::vector<std::pair<uint16_t, std::string>> extensions;
    return extensions;
}

// ============================================================================
// HTTP Host Header Extractor Implementation
// ============================================================================

bool HTTPHostExtractor::isHTTPRequest(const uint8_t* payload, size_t length) {
    if (length < 4) return false;
    
    // Check for common HTTP methods
    const char* methods[] = {"GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI"};
    
    for (const char* method : methods) {
        if (std::memcmp(payload, method, 4) == 0) {
            return true;
        }
    }
    
    return false;
}

std::optional<std::string> HTTPHostExtractor::extract(const uint8_t* payload, size_t length) {
    if (!isHTTPRequest(payload, length)) {
        return std::nullopt;
    }
    
    // Search for "Host: " header
    constexpr size_t host_header_len = 6;
    
    for (size_t i = 0; i + host_header_len < length; i++) {
        // Check for header (case-insensitive "host:")
        if ((payload[i] == 'H' || payload[i] == 'h') &&
            (payload[i+1] == 'o' || payload[i+1] == 'O') &&
            (payload[i+2] == 's' || payload[i+2] == 'S') &&
            (payload[i+3] == 't' || payload[i+3] == 'T') &&
            payload[i+4] == ':') {
            
            // Skip "Host:" and any whitespace
            size_t start = i + 5;
            while (start < length && (payload[start] == ' ' || payload[start] == '\t')) {
                start++;
            }
            
            // Find end of line
            size_t end = start;
            while (end < length && payload[end] != '\r' && payload[end] != '\n') {
                end++;
            }
            
            if (end > start) {
                std::string host(reinterpret_cast<const char*>(payload + start), end - start);
                
                // Remove port if present
                size_t colon_pos = host.find(':');
                if (colon_pos != std::string::npos) {
                    host = host.substr(0, colon_pos);
                }
                
                return host;
            }
        }
    }
    
    return std::nullopt;
}

// ============================================================================
// DNS Extractor Implementation
// ============================================================================

bool DNSExtractor::isDNSQuery(const uint8_t* payload, size_t length) {
    // Minimum DNS header is 12 bytes
    if (length < 12) return false;
    
    // Check QR bit (byte 2, bit 7) - should be 0 for query
    uint8_t flags = payload[2];
    if (flags & 0x80) return false;  // This is a response, not a query
    
    // Check QDCOUNT (bytes 4-5) - should be > 0
    uint16_t qdcount = (static_cast<uint16_t>(payload[4]) << 8) | payload[5];
    if (qdcount == 0) return false;
    
    return true;
}

std::optional<std::string> DNSExtractor::extractQuery(const uint8_t* payload, size_t length) {
    if (!isDNSQuery(payload, length)) {
        return std::nullopt;
    }
    
    // DNS query starts at byte 12
    size_t offset = 12;
    std::string domain;
    
    while (offset < length) {
        uint8_t label_length = payload[offset];
        
        if (label_length == 0) {
            // End of domain name
            break;
        }
        
        if (label_length > 63) {
            // Compression pointer or invalid
            break;
        }
        
        offset++;
        if (offset + label_length > length) break;
        
        if (!domain.empty()) {
            domain += '.';
        }
        domain += std::string(reinterpret_cast<const char*>(payload + offset), label_length);
        offset += label_length;
    }
    
    return domain.empty() ? std::nullopt : std::optional<std::string>(domain);
}

// ============================================================================
// QUIC SNI Extractor (simplified)
// ============================================================================

bool QUICSNIExtractor::isQUICInitial(const uint8_t* payload, size_t length) {
    if (length < 5) return false;
    
    // QUIC long header starts with 1 bit set (form bit)
    // and the type should be Initial (0x00)
    uint8_t first_byte = payload[0];
    
    // Long header form
    if ((first_byte & 0x80) == 0) return false;
    
    // Check for QUIC version (bytes 1-4)
    // Common versions: 0x00000001 (v1), 0xff000000+ (drafts)
    // We'll be lenient here
    
    return true;
}

std::optional<std::string> QUICSNIExtractor::extract(const uint8_t* payload, size_t length) {
    if (!isQUICInitial(payload, length)) {
        return std::nullopt;
    }
    
    // Search for TLS Client Hello (Handshake Type 0x01) inside QUIC Initial / CRYPTO frames
    for (size_t i = 0; i + 40 < length; i++) {
        if (payload[i] == 0x01) {  // Client Hello handshake type
            auto result = SNIExtractor::extractFromClientHello(payload + i, length - i);
            if (result) return result;
        }
    }
    
    return std::nullopt;
}

} // namespace DPI
