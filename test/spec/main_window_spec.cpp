#include <bandit_with_gmock/bandit_with_gmock.hpp>
#include <twit4v/main_window.hpp>

namespace Twit4v {
go_bandit([]{
    using namespace bandit;
    
    describe("MainWindow", [&]{
        it("should be true", [&]{
            AssertThat(true, Equals(true));
        });
    });
});
}
