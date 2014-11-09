#include <twit4v/net/session/oauth.hpp>
#include <twit4v/net/session/detail/oauth.hpp>
#include <twit4v/net/percent_encoding.hpp>
#include <boost/range/algorithm.hpp>

namespace twit4v { namespace net { namespace session {
    using namespace boost::network;
    
    oauth::oauth(std::initializer_list<parameter::value_type> params) {
        for (auto && pair: params) {
            if (this->oauth_params.find(pair.first) == this->oauth_params.end()) continue;
            this->oauth_params[pair.first] = pair.second;
        }
    }
    
    void oauth::set_authorizer(authorizer_type authorizer) {
        this->authorizer = authorizer;
    }
    
    void oauth::authorize() {
        if (this->authorizer) this->authorizer(*this);
    }
    
    oauth::value_type & oauth::operator[](std::string const & key) {
        return this->oauth_params.at(key);
    }
    
    oauth::value_type const & oauth::operator[](std::string const & key) const {
        return this->oauth_params.at(key);
    }
    
    parameter oauth::send_params(std::vector<std::string> const & exclusions) const {
        parameter result;
        for (auto && pair: this->oauth_params) {
            if (!pair.second) continue;
            if (pair.first == "oauth_consumer_secret") continue;
            if (pair.first == "oauth_token_secret") continue;
            if (boost::find(exclusions, pair.first) != exclusions.end()) continue;
            result[pair.first] = *pair.second;
        }
        return result;
    }
    
    client::request & oauth::attach_to(client::request & request, std::string const & method) {
        using namespace detail::oauth;
        auto && that = *this;
        that["oauth_nonce"] = nonce();
        that["oauth_timestamp"] = timestamp();
        that["oauth_signature"] = signature(that, request, method);
        request << header("Authorization", authorization_header(that));
        return request;
    }
}}}
