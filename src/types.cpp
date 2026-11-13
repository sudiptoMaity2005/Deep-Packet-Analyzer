#include "types.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

namespace DPI {

std::string FiveTuple::toString() const {
    std::ostringstream ss;
    
    // Format IP addresses
    auto formatIPv4 = [](uint32_t ip) {
        std::ostringstream s;
        s << ((ip >> 0) & 0xFF) << "."
          << ((ip >> 8) & 0xFF) << "."
          << ((ip >> 16) & 0xFF) << "."
          << ((ip >> 24) & 0xFF);
        return s.str();
    };
    
    auto formatIPv6 = [](const std::array<uint8_t, 16>& b) {
        std::ostringstream s;
        s << std::hex << std::setfill('0');
        for (size_t i = 0; i < 16; i += 2) {
            if (i > 0) s << ":";
            uint16_t w = (b[i] << 8) | b[i+1];
            s << w;
        }
        return s.str();
    };
    
    if (ip_version == 6) {
        ss << "[" << formatIPv6(src_ip6) << "]:" << src_port
           << " -> ["
           << formatIPv6(dst_ip6) << "]:" << dst_port;
    } else {
        ss << formatIPv4(src_ip) << ":" << src_port
           << " -> "
           << formatIPv4(dst_ip) << ":" << dst_port;
    }
    
    ss << " (" << (protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "?") << ")";
    return ss.str();
}

std::string appTypeToString(AppType type) {
    switch (type) {
        case AppType::UNKNOWN:    return "Unknown";
        case AppType::HTTP:       return "HTTP";
        case AppType::HTTPS:      return "HTTPS";
        case AppType::DNS:        return "DNS";
        case AppType::TLS:        return "TLS";
        case AppType::QUIC:       return "QUIC";
        case AppType::GOOGLE:     return "Google";
        case AppType::FACEBOOK:   return "Facebook";
        case AppType::YOUTUBE:    return "YouTube";
        case AppType::TWITTER:    return "Twitter/X";
        case AppType::INSTAGRAM:  return "Instagram";
        case AppType::NETFLIX:    return "Netflix";
        case AppType::AMAZON:     return "Amazon";
        case AppType::MICROSOFT:  return "Microsoft";
        case AppType::APPLE:      return "Apple";
        case AppType::WHATSAPP:   return "WhatsApp";
        case AppType::TELEGRAM:   return "Telegram";
        case AppType::TIKTOK:     return "TikTok";
        case AppType::SPOTIFY:    return "Spotify";
        case AppType::ZOOM:       return "Zoom";
        case AppType::DISCORD:    return "Discord";
        case AppType::GITHUB:     return "GitHub";
        case AppType::CLOUDFLARE: return "Cloudflare";
        case AppType::CHATGPT:    return "ChatGPT";
        case AppType::CLAUDE:     return "Claude";
        case AppType::REDDIT:     return "Reddit";
        case AppType::LINKEDIN:   return "LinkedIn";
        case AppType::TWITCH:     return "Twitch";
        case AppType::SLACK:      return "Slack";
        default:                  return "Unknown";
    }
}

// Helper: check if host exactly equals domain or is a subdomain of domain (e.g. host="api.x.com", domain="x.com" -> true; host="netflix.com", domain="x.com" -> false)
static bool matchesDomain(const std::string& host, const std::string& domain) {
    if (host == domain) return true;
    if (host.size() > domain.size() + 1) {
        if (host.compare(host.size() - domain.size(), domain.size(), domain) == 0) {
            return host[host.size() - domain.size() - 1] == '.';
        }
    }
    return false;
}

// Helper: check if host contains keyword bounded by '.' or '-' or string boundaries
static bool containsKeyword(const std::string& host, const std::string& kw) {
    auto pos = host.find(kw);
    while (pos != std::string::npos) {
        bool left_ok = (pos == 0 || host[pos - 1] == '.' || host[pos - 1] == '-');
        size_t right_pos = pos + kw.size();
        bool right_ok = (right_pos == host.size() || host[right_pos] == '.' || host[right_pos] == '-');
        if (left_ok && right_ok) {
            return true;
        }
        pos = host.find(kw, pos + 1);
    }
    return false;
}

// Map SNI/domain to application type
AppType sniToAppType(const std::string& sni) {
    if (sni.empty()) return AppType::UNKNOWN;
    
    // Convert to lowercase for matching
    std::string lower_sni = sni;
    std::transform(lower_sni.begin(), lower_sni.end(), lower_sni.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    
    // 1. YouTube (check before general Google)
    if (matchesDomain(lower_sni, "youtube.com") ||
        matchesDomain(lower_sni, "youtu.be") ||
        matchesDomain(lower_sni, "ytimg.com") ||
        matchesDomain(lower_sni, "yt3.ggpht.com") ||
        containsKeyword(lower_sni, "youtube")) {
        return AppType::YOUTUBE;
    }
    
    // 2. Google
    if (matchesDomain(lower_sni, "google.com") ||
        matchesDomain(lower_sni, "gstatic.com") ||
        matchesDomain(lower_sni, "googleapis.com") ||
        matchesDomain(lower_sni, "ggpht.com") ||
        matchesDomain(lower_sni, "gvt1.com") ||
        containsKeyword(lower_sni, "google")) {
        return AppType::GOOGLE;
    }
    
    // 3. Instagram (check before general Facebook)
    if (matchesDomain(lower_sni, "instagram.com") ||
        matchesDomain(lower_sni, "cdninstagram.com") ||
        containsKeyword(lower_sni, "instagram")) {
        return AppType::INSTAGRAM;
    }
    
    // 4. WhatsApp
    if (matchesDomain(lower_sni, "whatsapp.com") ||
        matchesDomain(lower_sni, "whatsapp.net") ||
        matchesDomain(lower_sni, "wa.me") ||
        containsKeyword(lower_sni, "whatsapp")) {
        return AppType::WHATSAPP;
    }
    
    // 5. Facebook / Meta
    if (matchesDomain(lower_sni, "facebook.com") ||
        matchesDomain(lower_sni, "fbcdn.net") ||
        matchesDomain(lower_sni, "fb.com") ||
        matchesDomain(lower_sni, "fbsbx.com") ||
        matchesDomain(lower_sni, "meta.com") ||
        containsKeyword(lower_sni, "facebook")) {
        return AppType::FACEBOOK;
    }
    
    // 6. Twitter / X (strictly bounded to prevent matching netflix.com or microsoft.com)
    if (matchesDomain(lower_sni, "twitter.com") ||
        matchesDomain(lower_sni, "x.com") ||
        matchesDomain(lower_sni, "t.co") ||
        matchesDomain(lower_sni, "twimg.com") ||
        containsKeyword(lower_sni, "twitter")) {
        return AppType::TWITTER;
    }
    
    // 7. Netflix
    if (matchesDomain(lower_sni, "netflix.com") ||
        matchesDomain(lower_sni, "netflix.net") ||
        matchesDomain(lower_sni, "nflxvideo.net") ||
        matchesDomain(lower_sni, "nflximg.net") ||
        containsKeyword(lower_sni, "netflix")) {
        return AppType::NETFLIX;
    }
    
    // 8. Amazon / AWS
    if (matchesDomain(lower_sni, "amazon.com") ||
        matchesDomain(lower_sni, "amazonaws.com") ||
        matchesDomain(lower_sni, "cloudfront.net") ||
        matchesDomain(lower_sni, "aws.amazon.com") ||
        containsKeyword(lower_sni, "amazon")) {
        return AppType::AMAZON;
    }
    
    // 9. Microsoft
    if (matchesDomain(lower_sni, "microsoft.com") ||
        matchesDomain(lower_sni, "msn.com") ||
        matchesDomain(lower_sni, "office.com") ||
        matchesDomain(lower_sni, "office365.com") ||
        matchesDomain(lower_sni, "azure.com") ||
        matchesDomain(lower_sni, "live.com") ||
        matchesDomain(lower_sni, "outlook.com") ||
        matchesDomain(lower_sni, "bing.com") ||
        containsKeyword(lower_sni, "microsoft") ||
        containsKeyword(lower_sni, "azure")) {
        return AppType::MICROSOFT;
    }
    
    // 10. Apple
    if (matchesDomain(lower_sni, "apple.com") ||
        matchesDomain(lower_sni, "icloud.com") ||
        matchesDomain(lower_sni, "mzstatic.com") ||
        matchesDomain(lower_sni, "itunes.com") ||
        containsKeyword(lower_sni, "apple") ||
        containsKeyword(lower_sni, "icloud")) {
        return AppType::APPLE;
    }
    
    // 11. Telegram
    if (matchesDomain(lower_sni, "telegram.org") ||
        matchesDomain(lower_sni, "t.me") ||
        containsKeyword(lower_sni, "telegram")) {
        return AppType::TELEGRAM;
    }
    
    // 12. TikTok
    if (matchesDomain(lower_sni, "tiktok.com") ||
        matchesDomain(lower_sni, "tiktokcdn.com") ||
        matchesDomain(lower_sni, "musical.ly") ||
        matchesDomain(lower_sni, "bytedance.com") ||
        containsKeyword(lower_sni, "tiktok")) {
        return AppType::TIKTOK;
    }
    
    // 13. Spotify
    if (matchesDomain(lower_sni, "spotify.com") ||
        matchesDomain(lower_sni, "scdn.co") ||
        containsKeyword(lower_sni, "spotify")) {
        return AppType::SPOTIFY;
    }
    
    // 14. Zoom
    if (matchesDomain(lower_sni, "zoom.us") ||
        matchesDomain(lower_sni, "zoomgov.com") ||
        containsKeyword(lower_sni, "zoom")) {
        return AppType::ZOOM;
    }
    
    // 15. Discord
    if (matchesDomain(lower_sni, "discord.com") ||
        matchesDomain(lower_sni, "discord.gg") ||
        matchesDomain(lower_sni, "discordapp.com") ||
        matchesDomain(lower_sni, "discordapp.net") ||
        containsKeyword(lower_sni, "discord")) {
        return AppType::DISCORD;
    }
    
    // 16. GitHub
    if (matchesDomain(lower_sni, "github.com") ||
        matchesDomain(lower_sni, "githubusercontent.com") ||
        matchesDomain(lower_sni, "github.io") ||
        containsKeyword(lower_sni, "github")) {
        return AppType::GITHUB;
    }
    
    // 17. Cloudflare
    if (matchesDomain(lower_sni, "cloudflare.com") ||
        matchesDomain(lower_sni, "cloudflare-dns.com") ||
        matchesDomain(lower_sni, "1.1.1.1") ||
        containsKeyword(lower_sni, "cloudflare")) {
        return AppType::CLOUDFLARE;
    }
    
    // 18. ChatGPT / OpenAI
    if (matchesDomain(lower_sni, "chatgpt.com") ||
        matchesDomain(lower_sni, "openai.com") ||
        matchesDomain(lower_sni, "oaistatic.com") ||
        matchesDomain(lower_sni, "oaiusercontent.com") ||
        containsKeyword(lower_sni, "chatgpt") ||
        containsKeyword(lower_sni, "openai")) {
        return AppType::CHATGPT;
    }
    
    // 19. Claude / Anthropic
    if (matchesDomain(lower_sni, "claude.ai") ||
        matchesDomain(lower_sni, "anthropic.com") ||
        containsKeyword(lower_sni, "claude") ||
        containsKeyword(lower_sni, "anthropic")) {
        return AppType::CLAUDE;
    }
    
    // 20. Reddit
    if (matchesDomain(lower_sni, "reddit.com") ||
        matchesDomain(lower_sni, "redd.it") ||
        matchesDomain(lower_sni, "redditmedia.com") ||
        containsKeyword(lower_sni, "reddit")) {
        return AppType::REDDIT;
    }
    
    // 21. LinkedIn
    if (matchesDomain(lower_sni, "linkedin.com") ||
        matchesDomain(lower_sni, "licdn.com") ||
        containsKeyword(lower_sni, "linkedin")) {
        return AppType::LINKEDIN;
    }
    
    // 22. Twitch
    if (matchesDomain(lower_sni, "twitch.tv") ||
        matchesDomain(lower_sni, "ttvnw.net") ||
        containsKeyword(lower_sni, "twitch")) {
        return AppType::TWITCH;
    }
    
    // 23. Slack
    if (matchesDomain(lower_sni, "slack.com") ||
        matchesDomain(lower_sni, "slack-edge.com") ||
        matchesDomain(lower_sni, "slack-msgs.com") ||
        containsKeyword(lower_sni, "slack")) {
        return AppType::SLACK;
    }
    
    // If SNI is present but not recognized, still mark as TLS/HTTPS
    return AppType::HTTPS;
}

} // namespace DPI
