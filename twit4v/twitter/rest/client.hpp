#ifndef TWIT4V_TWITTER_REST_CLIENT_HPP
#define TWIT4V_TWITTER_REST_CLIENT_HPP

#include <iostream>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/optional.hpp>
#include <twit4v/net.hpp>

namespace twit4v { namespace twitter { namespace rest {
    template <typename Session>
    class client {
    public:
        using session_type = Session;
        
        client(session_type & session) : session(session) {}
        
        auto request(
            std::string const & method,
            std::string const & path,
            net::parameter params = {}
        ) {
            using namespace boost::network;
            using namespace boost::property_tree;
            static std::string const base_url = "https://api.twitter.com/1.1/";
            std::string const params_str = net::generate_www_form_urlencoded(params);
            
            // build url
            uri::uri url(base_url + path);
            if (method == "GET") url << uri::query(params_str);
            
            // build request
            net::client::request request(url);
            request
                << header("Content-Type", "application/x-www-form-urlencoded")
                << header("Connection", "close");
            if (method == "POST") request << body(params_str);
            
            // attach session
            this->session.attach_to(request, method);
            
            // http access
            net::client client;
            net::client::response response;
            if (method == "GET") {
                response = client.get(request);
            }
            else if (method == "POST") {
                std::string request_body = body(request);
                response = client.post(request, request_body);
            }
            
            // parse json
            ptree json;
            std::istringstream oss(body(response));
            json_parser::read_json(oss, json);
            
            return json;
        }
        
    protected:
        session_type session;
    };
}}}

#endif
