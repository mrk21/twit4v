#include <twit4v/twitter/auth/pin_based_oauth.hpp>

namespace twit4v { namespace twitter { namespace auth {
    pin_based_oauth::pin_based_oauth(pin_getter_type pin_getter) {
        if (pin_getter) {
            this->get_pin_from = pin_getter;
        }
        else {
            this->get_pin_from = [](boost::network::uri::uri url){
                std::cout << "URL: " << url.string() << std::endl;
                std::cout << "OAuth verifier: ";
                std::string oauth_verifier;
                std::cin >> oauth_verifier;
                std::cin.ignore();
                return oauth_verifier;
            };
        }
    }
    
    void pin_based_oauth::operator ()(net::oauth::session & session) {
        using namespace boost::network;
        
        session["oauth_signature_method"] = "HMAC-SHA1";
        
        // request token
        {
            session["oauth_callback"] = "oob";
            
            net::client::request request("https://api.twitter.com/oauth/request_token");
            request << header("Connection", "close");
            session.attach_to(request, "POST");
            
            net::client client;
            net::client::response response = client.post(request);
            net::parameter params = net::parse_www_form_urlencoded(http::body(response));
            
            session["oauth_token"] = params["oauth_token"];
            session["oauth_token_secret"] = params["oauth_token_secret"];
            session["oauth_callback"] = boost::none;
        }
        // authorize
        {
            uri::uri url("https://api.twitter.com/oauth/authorize");
            url << uri::query("oauth_token", *session["oauth_token"]);
            session["oauth_verifier"] = this->get_pin_from(std::move(url));
        }
        // access token
        {
            net::client::request request("https://api.twitter.com/oauth/access_token");
            request << header("Connection", "close");
            session.attach_to(request, "POST");
            
            net::client client;
            net::client::response response = client.post(request);
            net::parameter params = net::parse_www_form_urlencoded(http::body(response));
            
            session["oauth_token"] = params["oauth_token"];
            session["oauth_token_secret"] = params["oauth_token_secret"];
            session["oauth_verifier"] = boost::none;
        }
    }
}}}
