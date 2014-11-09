#ifndef TWIT4V_NET_SESSION_OAUTH_HPP
#define TWIT4V_NET_SESSION_OAUTH_HPP

#include <twit4v/net.hpp>
#include <string>
#include <vector>
#include <initializer_list>
#include <functional>
#include <boost/optional.hpp>

namespace twit4v { namespace net { namespace session {
    class oauth {
    public:
        using value_type = boost::optional<std::string>;
        using param_type = std::map<std::string, value_type>;
        using authorizer_type = std::function<void(oauth &)>;
        
    protected:
        param_type oauth_params{
            {"realm"                 , boost::none},
            {"oauth_consumer_key"    , boost::none},
            {"oauth_consumer_secret" , boost::none},
            {"oauth_token"           , boost::none},
            {"oauth_token_secret"    , boost::none},
            {"oauth_signature"       , boost::none},
            {"oauth_signature_method", boost::none},
            {"oauth_nonce"           , boost::none},
            {"oauth_timestamp"       , boost::none},
            {"oauth_version"         , boost::none},
            {"oauth_callback"        , boost::none},
            {"oauth_verifier"        , boost::none},
        };
        authorizer_type authorizer;
        
    public:
        oauth(std::initializer_list<parameter::value_type> params);
        void set_authorizer(authorizer_type authorizer);
        void authorize();
        value_type       & operator[](std::string const & key);
        value_type const & operator[](std::string const & key) const;
        parameter send_params(std::vector<std::string> const & exclusions = {}) const;
        client::request & attach_to(client::request & request, std::string const & method);
    };
}}}

#endif
