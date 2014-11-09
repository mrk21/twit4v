#include <twit4v/net.hpp>
#include <twit4v/net/percent_encoding.hpp>
#include <sstream>
#include <iomanip>
#include <boost/format.hpp>
#include <boost/algorithm/string.hpp>

namespace twit4v { namespace net {
    using namespace boost::network;
    using encoding = percent_encoding::basic_encoding<percent_encoding::www_form_urlencoded_policy>;
    
    std::string generate_www_form_urlencoded(parameter const & params) {
        std::vector<std::string> result;
        for (auto && pair: params) {
            result.push_back((boost::format("%s=%s")
                % encoding::encode(pair.first)
                % encoding::encode(pair.second)
            ).str());
        }
        return boost::join(result, "&");
    }
    
    parameter parse_www_form_urlencoded(std::string target) {
        boost::trim(target);
        
        parameter result;
        std::vector<std::string> params;
        boost::split(params, target, boost::is_any_of("&"));
        if (params.size() == 1 && params[0] == "") return {};
        
        for (auto && param: params) {
            std::vector<std::string> pair;
            boost::split(pair, param, boost::is_any_of("="));
            result[encoding::decode(pair[0])] = encoding::decode(pair[1]);
        }
        return result;
    }
}}
