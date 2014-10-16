#ifndef TWIT4V_NET_PERCENT_ENCODING_HPP
#define TWIT4V_NET_PERCENT_ENCODING_HPP

#include <string>
#include <sstream>
#include <iomanip>
#include <cctype>
#include <boost/format.hpp>
#include <boost/optional.hpp>

namespace twit4v { namespace net { namespace percent_encoding {
    struct basic_policy {
        static bool cannot_encode(char c) { return std::isalnum(c); }
        static boost::optional<char> special_encode(char c) { return boost::none; }
        static boost::optional<char> special_decode(char c) { return boost::none; }
    };
    
    // see: RFC3986, 2.1
    struct rfc3986_policy: public basic_policy {
        static bool cannot_encode(char c) {
            return std::isalnum(c) || c == '-' || c == '.' || c == '_' || c == '~';
        }
    };
    
    // see: RFC5849, 3.6
    struct rfc5849_policy: public rfc3986_policy {};
    
    // see: http://www.w3.org/TR/html401/interact/forms.html, 17.13.4
    struct www_form_urlencoded_policy: public basic_policy {
        static boost::optional<char> special_encode(char c) {
            if (c == ' ') return '+';
            return boost::none;
        }
        
        static boost::optional<char> special_decode(char c) {
            if (c == '+') return ' ';
            return boost::none;
        }
    };
    
    template<typename Policy>
    struct basic_encoding {
        static std::string encode(std::string const & value) {
            std::ostringstream oss;
            for (auto c: value) {
                if (Policy::cannot_encode(c)) {
                    oss << c;
                }
                else if (auto v = Policy::special_encode(c)) {
                    oss << *v;
                }
                else {
                    oss << boost::format("%%%02X") % static_cast<int>(c & 0xFF);
                }
            }
            return oss.str();
        }
        
        static std::string decode(std::string const & value) {
            std::istringstream iss(value);
            std::ostringstream oss;
            while (true) {
                char c;
                iss >> c;
                if (iss.eof()) break;
                if (c == '%') {
                    std::string s;
                    iss >> std::setw(2) >> s;
                    int v;
                    std::istringstream(s) >> std::hex >> v;
                    oss << static_cast<char>(v);
                }
                else if (auto v = Policy::special_decode(c)) {
                    oss << *v;
                }
                else {
                    oss << c;
                }
            }
            return oss.str();
        }
    };
}}}

#endif
