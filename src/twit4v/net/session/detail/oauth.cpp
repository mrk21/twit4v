#include <twit4v/net/session/detail/oauth.hpp>
#include <twit4v/net/percent_encoding.hpp>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <boost/format.hpp>
#include <boost/range/algorithm.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/network/utils/base64/encode.hpp>
#include <openssl/sha.h>
#include <openssl/hmac.h>

namespace twit4v { namespace net { namespace session { namespace detail { namespace oauth {
    using namespace boost::network;
    using percent_encoding = percent_encoding::basic_encoding<percent_encoding::rfc5849_policy>;
    
    // see: RFC5849, 3.4.2
    std::string hmac_sha1(std::string const & key, std::string const & text) {
        std::string digest(SHA_DIGEST_LENGTH + 1, '\0');
        unsigned int length;
        HMAC(
            EVP_sha1(),
            (const unsigned char *)key.data(), key.length(),
            (const unsigned char *)text.data(), text.length(),
            (unsigned char *)digest.data(), &length
        );
        digest.erase(length); 
        return utils::base64::encode<char>(digest);
    }
    
    // see: RFC5849, 3.5.1
    std::string authorization_header(session::oauth const & session) {
        std::vector<std::string> params;
        
        for (auto && pair: session.send_params()) {
            params.push_back((boost::format("%s=\"%s\"")
                % percent_encoding::encode(pair.first)
                % percent_encoding::encode(pair.second)
            ).str());
        }
        return "OAuth " + boost::algorithm::join(params, ",");
    }
    
    // see: RFC5849, 3.3
    // note: The returned timestamp is not based 1970-01-01 00:00:00 GMT but based 1970-01-01 00:00:00 UTC.
    std::string timestamp() {
        using namespace std::chrono;
        
        auto now = system_clock::now();
        auto epoch = duration_cast<seconds>(now.time_since_epoch());
        
        return boost::lexical_cast<std::string>(epoch.count());
    }
    
    // see: RFC5849, 3.3
    std::string nonce() {
        return boost::lexical_cast<std::string>(boost::uuids::random_generator()());
    }
    
    // see: RFC5849, 3.4.2
    // note: Supported signature methods are only "HMAC-SHA1".
    session::oauth::value_type signature(
        session::oauth const & session,
        client::request const & request,
        std::string const & method
    ) {
        if (auto signature_method = session["oauth_signature_method"]) {
            if (*signature_method == "HMAC-SHA1") {
                std::string key;
                if (auto v = session["oauth_consumer_secret"]) { key += *v; } key += "&";
                if (auto v = session["oauth_token_secret"   ]) { key += *v; }
                return hmac_sha1(key, signature_base_string(session, request, method));
            }
        }
        return boost::none;
    }
    
    // see: RFC5849, 3.4.1
    std::string signature_base_string(
        session::oauth const & session,
        client::request const & request,
        std::string const & method
    ) {
        auto content_types = headers(request)["Content-Type"];
        std::string content_type = "";
        if (!content_types.empty()) content_type = content_types.front().second;
        parameter oauth_params = session.send_params({"realm","oauth_signature"});
        
        // base string URI (see: RFC5849, 3.4.1.2)
        uri::uri base_string_uri;
        base_string_uri
            << uri::scheme(request.uri().scheme())
            << uri::host(request.uri().host())
            << uri::path(request.uri().path());
        
        // request parameter (see: RFC5849, 3.4.1.3)
        std::vector<std::string> params;
        auto push_param = [&params](auto && pair){
            params.push_back((boost::format("%s=%s")
                % percent_encoding::encode(pair.first)
                % percent_encoding::encode(pair.second)
            ).str());
        };
        boost::for_each(parse_www_form_urlencoded(request.uri().query()), push_param);
        boost::for_each(oauth_params, push_param);
        if (content_type == "application/x-www-form-urlencoded") {
            boost::for_each(parse_www_form_urlencoded(body(request)), push_param);
        }
        std::string request_parameter = boost::join(boost::sort(params), "&");
        
        // signature base string
        return (std::ostringstream()
            << percent_encoding::encode(method) << '&'
            << percent_encoding::encode(base_string_uri.string()) << '&'
            << percent_encoding::encode(request_parameter)
        ).str();
    }
}}}}}
