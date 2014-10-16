#include <bandit_with_gmock/bandit_with_gmock.hpp>
#include <twit4v/net/percent_encoding.hpp>

namespace twit4v { namespace net { namespace percent_encoding {
    namespace percent_encoding_test {
        std::string const URI_UNRESERVED = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"; // see: RFC3986, 2.3
        
        std::string const OTHER_SIGN = "!\"#$%&\'()*+,/:;<=>?@[\\]^`{|}";
        std::string const ENCODED_OTHER_SIGN = "%21%22%23%24%25%26%27%28%29%2A%2B%2C%2F%3A%3B%3C%3D%3E%3F%40%5B%5C%5D%5E%60%7B%7C%7D";
        
        std::string const WHITE_SPACE = " \t\n\r";
        std::string const ENCODED_WHITE_SPACE = "%20%09%0A%0D";
        
        std::string const UTF8 = u8"あいうえお　";
        std::string const ENCODED_UTF8 = "%E3%81%82%E3%81%84%E3%81%86%E3%81%88%E3%81%8A%E3%80%80";
    }
    
go_bandit([]{
    using namespace bandit;
    
    describe("twit4v::net::percent_encoding::basic_encoding<Policy>", [&]{
        using namespace percent_encoding_test;
        
        describe("when the Policy was rfc5849_policy", [&]{
            using encoding = basic_encoding<rfc5849_policy>;
            
            describe("::encode(value)", [&]{
                describe("URI Unreserved Characters", [&]{
                    it("should not encode", [&]{
                        AssertThat(encoding::encode(URI_UNRESERVED), Equals(URI_UNRESERVED));
                    });
                });
                
                describe("other sign characters", [&]{
                    it("should encode", [&]{
                        AssertThat(encoding::encode(OTHER_SIGN), Equals(ENCODED_OTHER_SIGN));
                    });
                });
                
                describe("white spaces", [&]{
                    it("should encode", [&]{
                        AssertThat(encoding::encode(WHITE_SPACE), Equals(ENCODED_WHITE_SPACE));
                    });
                });
                
                describe("UTF-8 encoded Unicode characters", [&]{
                    it("should encode", [&]{
                        AssertThat(encoding::encode(UTF8), Equals(ENCODED_UTF8));
                    });
                });
            });
            
            describe("::decode(target)", [&]{
                describe("URI Unreserved Characters", [&]{
                    it("should not decode", [&]{
                        AssertThat(encoding::decode(URI_UNRESERVED), Equals(URI_UNRESERVED));
                    });
                });
                
                describe("other sign characters", [&]{
                    it("should decode", [&]{
                        AssertThat(encoding::decode(ENCODED_OTHER_SIGN), Equals(OTHER_SIGN));
                    });
                });
                
                describe("white spaces", [&]{
                    it("should decode", [&]{
                        AssertThat(encoding::decode(ENCODED_WHITE_SPACE), Equals(WHITE_SPACE));
                    });
                });
                
                describe("UTF-8 encoded Unicode characters", [&]{
                    it("should decode", [&]{
                        AssertThat(encoding::decode(ENCODED_UTF8), Equals(UTF8));
                    });
                });
                
                describe("When alphabets of A to F were existed after encoded characters", [&]{
                    it("should not involve the alphabets", [&]{
                        AssertThat(encoding::decode("%7DDEF"), Equals("}DEF"));
                    });
                });
            });
        });
        
        describe("when the Policy was www_form_urlencoded_policy", [&]{
            using encoding = basic_encoding<www_form_urlencoded_policy>;
            std::string const DECODED = "ab cd+ef";
            std::string const ENCODED = "ab+cd%2Bef";
            
            describe("::encode(value)", [&]{
                it("should encode ' ' to '+'", [&]{
                    AssertThat(encoding::encode(DECODED), Equals(ENCODED));
                });
            });
            
            describe("::decode(target)", [&]{
                it("should decode '+' to ' '", [&]{
                    AssertThat(encoding::decode(ENCODED), Equals(DECODED));
                });
            });
        });
    });
});
}}}
