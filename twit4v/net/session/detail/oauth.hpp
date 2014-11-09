#ifndef TWIT4V_NET_SESSION_DETAIL_OAUTH_HPP
#define TWIT4V_NET_SESSION_DETAIL_OAUTH_HPP

#include <twit4v/net.hpp>
#include <twit4v/net/session/oauth.hpp>
#include <string>

namespace twit4v { namespace net { namespace session { namespace detail { namespace oauth {
    std::string hmac_sha1(std::string const & key, std::string const & text);
    
    std::string authorization_header(session::oauth const & session);
    std::string timestamp();
    std::string nonce();
    
    session::oauth::value_type signature(
        session::oauth const & session,
        client::request const & request,
        std::string const & method
    );
    
    std::string signature_base_string(
        session::oauth const & session,
        client::request const & request,
        std::string const & method
    );
}}}}}

#endif
