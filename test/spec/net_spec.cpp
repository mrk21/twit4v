#include <bandit_with_gmock/bandit_with_gmock.hpp>
#include <twit4v/net.hpp>

namespace twit4v { namespace net {
    namespace www_form_urlencoded_test {
        std::string const STR = "a3=2+q&c2=";
        parameter const PARAMS{
            {"a3", "2 q"},
            {"c2", ""},
        };
    }
    
go_bandit([]{
    using namespace bandit;
    
    describe("twit4v::net", []{
        describe("generate_www_form_urlencoded(params)", [&]{
            using namespace www_form_urlencoded_test;
            
            it("should generate a parameter", [&]{
                AssertThat(generate_www_form_urlencoded(PARAMS), Equals(STR));
            });
            
            describe("when the params was empty", [&]{
                it("should be empty string", [&]{
                    AssertThat(generate_www_form_urlencoded({}), Equals(""));
                });
            });
        });
        
        describe("parse_www_form_urlencoded(target)", [&]{
            using namespace www_form_urlencoded_test;
            
            it("should split to a parameter", [&]{
                AssertThat(parse_www_form_urlencoded(STR), Equals(PARAMS));
            });
            
            describe("when the target contained white spaces on both ends", [&]{
                it("should remove the spaces before splitting", [&]{
                    AssertThat(parse_www_form_urlencoded(" "+ STR +"   "), Equals(PARAMS));
                });
            });
            describe("when the target was empty", [&]{
                it("should be an empty parameter", [&]{
                    AssertThat(parse_www_form_urlencoded(""), Equals(parameter{}));
                });
            });
        });
    });
});
}}
