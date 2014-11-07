#ifndef TWIT4V_TWITTER_AUTH_PIN_BASED_OAUTH_HPP
#define TWIT4V_TWITTER_AUTH_PIN_BASED_OAUTH_HPP

#include <string>
#include <functional>
#include <twit4v/net/oauth.hpp>

namespace twit4v { namespace twitter { namespace auth {
    struct pin_based_oauth {
        using pin_getter_type = std::function<std::string(boost::network::uri::uri)>;
        
        pin_based_oauth(pin_getter_type pin_getter = nullptr);
        void operator ()(net::oauth::session & session);
        
    protected:
        pin_getter_type get_pin_from;
    };
}}}

#endif
