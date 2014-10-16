#include <twit4v/net/oauth.hpp>
#include <twit4v/net/percent_encoding.hpp>
#include <sstream>
#include <iomanip>
#include <cctype>
#include <boost/format.hpp>
#include <boost/range/algorithm.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/date_time.hpp>
#include <boost/date_time/c_local_time_adjustor.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/network/utils/base64/encode.hpp>
#include <openssl/sha.h>
#include <openssl/hmac.h>

namespace twit4v { namespace net { namespace oauth {
    using namespace boost::network;
    
    session::session(std::initializer_list<parameter::value_type> params) {
        for (auto & pair: params) {
            if (this->oauth_params.find(pair.first) == this->oauth_params.end()) continue;
            this->oauth_params[pair.first] = pair.second;
        }
    }
    
    session::value_type & session::operator[](std::string const & key) {
        return this->oauth_params.at(key);
    }
    
    session::value_type const & session::operator[](std::string const & key) const {
        return this->oauth_params.at(key);
    }
    
    parameter session::send_params(std::vector<std::string> const & exclusions) const {
        parameter result;
        for (auto & pair: this->oauth_params) {
            if (!pair.second) continue;
            if (pair.first == "oauth_consumer_secret") continue;
            if (pair.first == "oauth_token_secret") continue;
            if (boost::find(exclusions, pair.first) != exclusions.end()) continue;
            result[pair.first] = *pair.second;
        }
        return result;
    }
    
    client::request & session::authorize(client::request & request, std::string method) {
        auto & that = *this;
        that["oauth_nonce"] = detail::nonce();
        that["oauth_timestamp"] = detail::timestamp();
        that["oauth_signature"] = detail::signature(that, request, method);
        request << header("Authorization", detail::authorization_header(that));
        return request;
    }
    
    namespace detail {
        using percent_encoding = percent_encoding::basic_encoding<percent_encoding::rfc5849_policy>;
        
        // see: RFC5849, 3.4.2
        std::string hmac_sha1(std::string const & value, std::string const & key) {
            std::string result(SHA_DIGEST_LENGTH + 1, '\0');
            unsigned int length;
            HMAC(
                EVP_sha1(),
                (const unsigned char *)key.data(), key.length(),
                (const unsigned char *)value.data(), value.length(),
                (unsigned char *)result.data(), &length
            );
            result.erase(length); 
            return result;
        }
        
        // see: RFC5849, 3.5.1
        std::string authorization_header(oauth::session const & session) {
            std::vector<std::string> params;
            
            for (auto & pair: session.send_params()) {
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
            using namespace boost::posix_time;
            using namespace boost::gregorian;
            
            auto epoch = ptime(date(1970,1,1));
            auto diff = second_clock::local_time() - epoch;
            
            return boost::lexical_cast<std::string>(diff.total_seconds());
        }
        
        // see: RFC5849, 3.3
        std::string nonce() {
            return boost::lexical_cast<std::string>(boost::uuids::random_generator()());
        }
        
        // see: RFC5849, 3.4.2
        // note: Supported signature methods are only "HMAC-SHA1".
        std::string signature(
            oauth::session const & session,
            client::request const & request,
            std::string method
        ) {
            if (auto signature_method = session["oauth_signature_method"]) {
                if (*signature_method == "HMAC-SHA1") {
                    std::string key;
                    if (auto v = session["oauth_consumer_secret"]) key += *v;
                    key += "&";
                    if (auto v = session["oauth_token_secret"]) key += *v;
                    auto base = signature_base_string(session, request, method);
                    return utils::base64::encode<char>(hmac_sha1(base, key));
                }
            }
            return "";
        }
        
        // see: RFC5849, 3.4.1
        std::string signature_base_string(
            oauth::session const & session,
            client::request const & request,
            std::string method
        ) {
            auto content_types = headers(request)["Content-Type"];
            std::string content_type = "";
            if (!content_types.empty()) content_type = content_types.front().second;
            parameter oauth_params = session.send_params({"realm","oauth_signature"});
            
            // base string URI
            uri::uri base_string_uri;
            base_string_uri
                << uri::scheme(request.uri().scheme())
                << uri::host(request.uri().host())
                << uri::path(request.uri().path());
            
            // request parameter
            std::vector<std::string> params;
            auto push_param = [&params](auto & pair){
                params.push_back(percent_encoding::encode(pair.first) +"="+ percent_encoding::encode(pair.second));
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
    }
}}}
