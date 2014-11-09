#include <bandit_with_gmock/bandit_with_gmock.hpp>
#include <twit4v/net/session/detail/oauth.hpp>

namespace twit4v { namespace net { namespace session { namespace detail { namespace oauth {
    using namespace boost::network;
    
    namespace signature_base_string_test {
        std::string const URI = "http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b";
        std::string const WWW_FORM_URLENCODED_BODY = "c2&a3=2+q";
        std::string const JSON_BODY = "{\"c2\": \"\", \"a3\": \"2 q\"}";
        session::oauth const SESSION{
            {"oauth_consumer_key", "9djdj82h48djs9d2"},
            {"oauth_token", "kkk9d7dh3k39sjv7"},
            {"oauth_signature_method", "HMAC-SHA1"},
            {"oauth_timestamp", "137131201"},
            {"oauth_nonce", "7d8f3e4a"},
        };
        session::oauth const SESSION_WITH_SIGNATURE_AND_REALM{
            {"realm", "Example"},
            {"oauth_consumer_key", "9djdj82h48djs9d2"},
            {"oauth_token", "kkk9d7dh3k39sjv7"},
            {"oauth_signature_method", "HMAC-SHA1"},
            {"oauth_timestamp", "137131201"},
            {"oauth_nonce", "7d8f3e4a"},
            {"oauth_signature", "djosJKDKJSD8743243%2Fjdk33klY%3D"},
        };
        std::string const METHOD = "GET";
        std::string const SIGNATURE_BASE =
            "GET&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26"
            "a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26oauth_consumer_k"
            "ey%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26oauth_signature_me"
            "thod%3DHMAC-SHA1%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk9"
            "d7dh3k39sjv7";
        std::string const SIGNATURE_BASE_WITH_BODY_PARAM =
            "GET&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q%"
            "26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_k"
            "ey%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26oauth_signature_me"
            "thod%3DHMAC-SHA1%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk9"
            "d7dh3k39sjv7";
    }
    
go_bandit([]{
    using namespace bandit;
    
    describe("twit4v::net::session::detail::oauth", []{
        describe("::signature(session, request, method)", [&]{
            using namespace signature_base_string_test;
            
            describe("when the session['oauth_signature_method'] was nothing", [&]{
                it("should be an invalid value", [&]{
                    auto session = SESSION;
                    auto request = client::request(URI);
                    session["oauth_signature_method"] = boost::none;
                    AssertThat(static_cast<bool>(signature(session, request, METHOD)), Equals(false));
                });
            });
            
            describe("when the session['oauth_signature_method'] was 'HMAC-SHA1'", [&]{
                it("should be a valid value", [&]{
                    auto session = SESSION;
                    auto request = client::request(URI);
                    AssertThat(static_cast<bool>(signature(session, request, METHOD)), Equals(true));
                });
            });
            
            describe("when the session['oauth_signature_method'] was other", [&]{
                it("should be an invalid value", [&]{
                    auto session = SESSION;
                    auto request = client::request(URI);
                    session["oauth_signature_method"] = "RSA-SHA1";
                    AssertThat(static_cast<bool>(signature(session, request, METHOD)), Equals(false));
                });
            });
        });
        
        describe("::signature_base_string(session, request, method)", [&]{
            using namespace signature_base_string_test;
            
            it("should generate", [&]{
                AssertThat(
                    signature_base_string(SESSION, client::request(URI), METHOD),
                    Equals(SIGNATURE_BASE)
                );
            });
            
            describe("with a request body of 'application/x-www-form-urlencoded'", [&]{
                it("should contain the body params", [&]{
                    client::request request(URI);
                    request
                        << header("Content-Type", "application/x-www-form-urlencoded")
                        << body(WWW_FORM_URLENCODED_BODY);
                    
                    AssertThat(
                        signature_base_string(SESSION, request, METHOD),
                        Equals(SIGNATURE_BASE_WITH_BODY_PARAM)
                    );
                });
            });
            
            describe("with a request body of other content-type", [&]{
                it("should not contain the body params", [&]{
                    client::request request(URI);
                    request
                        << header("Content-Type", "application/json")
                        << body(JSON_BODY);
                    
                    AssertThat(
                        signature_base_string(SESSION, request, METHOD),
                        Equals(SIGNATURE_BASE)
                    );
                });
            });
            
            describe("with oauth params of 'realm' and 'oauth_signature'", [&]{
                it("should not contain the params", [&]{
                    AssertThat(
                        signature_base_string(
                            SESSION_WITH_SIGNATURE_AND_REALM,
                            client::request(URI),
                            METHOD
                        ),
                        Equals(SIGNATURE_BASE)
                    );
                });
            });
        });
    });
});
}}}}}
