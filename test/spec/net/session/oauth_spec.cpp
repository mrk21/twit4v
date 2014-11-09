#include <bandit_with_gmock/bandit_with_gmock.hpp>
#include <twit4v/net/session/oauth.hpp>

namespace twit4v { namespace net { namespace session {
go_bandit([]{
    using namespace bandit;
    using namespace boost::network;
    
    describe("twit4v::net::session::oauth", []{
        describe("#send_params([exclusions])", [&]{
            it("should exclude parameters which have an invalid value", [&]{
                oauth instance{
                    {"oauth_consumer_key", "c"},
                    {"oauth_token", "t"},
                };
                parameter expected{
                    {"oauth_consumer_key", "c"},
                    {"oauth_token", "t"},
                };
                AssertThat(instance.send_params(), Equals(expected));
            });
            
            it("should exclude parameters of 'oauth_consumer_secret' and 'oauth_token_secret'", [&]{
                oauth instance{
                    {"oauth_consumer_key", "c"},
                    {"oauth_consumer_secret", "cs"},
                    {"oauth_token", "t"},
                    {"oauth_token_secret", "ts"},
                };
                parameter expected{
                    {"oauth_consumer_key", "c"},
                    {"oauth_token", "t"},
                };
                AssertThat(instance.send_params(), Equals(expected));
            });
            
            describe("with the exclusions", [&]{
                it("should exclude parameters which are designated by the exclusions", [&]{
                    oauth instance{
                        {"realm", "r"},
                        {"oauth_consumer_key", "c"},
                        {"oauth_token", "t"},
                        {"oauth_signature", "s"},
                    };
                    std::vector<std::string> exclusions{
                        "realm",
                        "oauth_signature"
                    };
                    parameter expected{
                        {"oauth_consumer_key", "c"},
                        {"oauth_token", "t"},
                    };
                    AssertThat(instance.send_params(exclusions), Equals(expected));
                });
            });
        });
    });
});
}}}
