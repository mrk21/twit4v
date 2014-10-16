#ifndef TWIT4V_NET_HPP
#define TWIT4V_NET_HPP

#include <string>
#include <map>
#include <boost/network/protocol/http/client.hpp>

namespace twit4v { namespace net {
    // [HTTP 1.1/TCP] async ver
    using client = boost::network::http::basic_client<boost::network::http::tags::http_async_8bit_tcp_resolve, 1, 1>;
    using parameter = std::map<std::string, std::string>;
    
    std::string generate_www_form_urlencoded(parameter const & params);
    parameter parse_www_form_urlencoded(std::string target);
}}

#endif
