#ifndef TWIT4V_NET_OAUTH_HPP
#define TWIT4V_NET_OAUTH_HPP

#include <twit4v/net.hpp>
#include <vector>
#include <initializer_list>
#include <boost/optional.hpp>

namespace twit4v { namespace net { namespace oauth {
    class session {
    public:
        using value_type = boost::optional<std::string>;
        using param_type = std::map<std::string, value_type>;
        
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
        
    public:
        session(std::initializer_list<parameter::value_type> params);
        value_type       & operator[](std::string const & key);
        value_type const & operator[](std::string const & key) const;
        parameter send_params(std::vector<std::string> const & exclusions = {}) const;
        client::request & authorize(client::request & request, std::string const & method);
    };
    
    namespace detail {
        std::string hmac_sha1(std::string const & key, std::string const & text);
        
        std::string authorization_header(oauth::session const & session);
        std::string timestamp();
        std::string nonce();
        
        oauth::session::value_type signature(
            oauth::session const & session,
            client::request const & request,
            std::string const & method
        );
        
        std::string signature_base_string(
            oauth::session const & session,
            client::request const & request,
            std::string const & method
        );
    }
}}}

#endif
