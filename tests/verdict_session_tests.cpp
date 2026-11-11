#include "VerdictSession.h"

#include <cstdlib>
#include <type_traits>
#include <utility>

namespace {

void Require(bool condition) {
    if (!condition) std::abort();
}

void TestRequestExistsOnlyInsideSession() {
    DriverVerdictSession sessions;

    DriverVerdictRequest absent = sessions.Receive(10);
    Require(!absent);

    const uint64_t session = sessions.Begin();
    DriverVerdictRequest request = sessions.Receive(10);
    Require(static_cast<bool>(request));
    Require(request.session() == session);
}

void TestZeroExternalIdIsValid() {
    DriverVerdictSession sessions;
    sessions.Begin();

    DriverVerdictRequest request = sessions.Receive(0);
    Require(static_cast<bool>(request));

    uint64_t id = 1;
    Require(sessions.Consume(request, id));
    Require(id == 0);
}

void TestMoveTransfersSingleObligation() {
    DriverVerdictSession sessions;
    sessions.Begin();

    DriverVerdictRequest original = sessions.Receive(12);
    DriverVerdictRequest moved(std::move(original));
    Require(!original);

    uint64_t id = 0;
    Require(sessions.Consume(moved, id));
    Require(id == 12);
}

void TestRequestCanBeConsumedOnlyOnce() {
    DriverVerdictSession sessions;
    sessions.Begin();

    DriverVerdictRequest request = sessions.Receive(42);
    uint64_t id = 0;
    Require(sessions.Consume(request, id));
    Require(id == 42);
    Require(!request);
    Require(!sessions.Consume(request, id));
}

void TestEndedSessionRejectsDelayedAnswer() {
    DriverVerdictSession sessions;
    const uint64_t session = sessions.Begin();
    DriverVerdictRequest request = sessions.Receive(63);

    Require(sessions.End(session) == session);
    uint64_t id = 0;
    Require(!sessions.Consume(request, id));
    Require(!request);
}

void TestOldSessionCannotAnswerNewDriver() {
    DriverVerdictSession sessions;
    const uint64_t oldSession = sessions.Begin();
    DriverVerdictRequest oldRequest = sessions.Receive(77);

    const uint64_t newSession = sessions.Begin();
    Require(newSession != oldSession);

    // Даже совпавший external_connection_id новой сессии не авторизует старый
    // объект: решение относится к конкретному событию и конкретному поколению.
    DriverVerdictRequest newRequest = sessions.Receive(77);
    uint64_t id = 0;
    Require(!sessions.Consume(oldRequest, id));
    Require(!oldRequest);
    Require(sessions.Consume(newRequest, id));
    Require(id == 77);
}

void TestLateDisconnectDoesNotEndNewSession() {
    DriverVerdictSession sessions;
    const uint64_t oldSession = sessions.Begin();
    const uint64_t newSession = sessions.Begin();

    Require(sessions.End(oldSession) == 0);
    Require(sessions.active() == newSession);
    Require(sessions.End(newSession) == newSession);
    Require(sessions.active() == 0);
}

void TestRequestBelongsToIssuingGate() {
    DriverVerdictSession first;
    DriverVerdictSession second;
    first.Begin();
    second.Begin();

    DriverVerdictRequest request = first.Receive(91);
    uint64_t id = 0;
    Require(!second.Consume(request, id));
    Require(!request);
}

void TestInspectPreservesObligation() {
    DriverVerdictSession sessions;
    sessions.Begin();
    DriverVerdictRequest request = sessions.Receive(123);

    uint64_t id = 0;
    Require(sessions.Inspect(request, id));
    Require(id == 123 && static_cast<bool>(request));
    Require(sessions.Inspect(request, id));
    Require(sessions.Consume(request, id));
    Require(id == 123);
    Require(!sessions.Inspect(request, id));
}

void TestInspectAcceptsZeroExternalId() {
    DriverVerdictSession sessions;
    sessions.Begin();
    DriverVerdictRequest request = sessions.Receive(0);

    uint64_t id = 1;
    Require(sessions.Inspect(request, id));
    Require(id == 0);
    Require(sessions.Consume(request, id));
}

void TestInspectRejectsStaleAndForeignRequests() {
    DriverVerdictSession sessions;
    const uint64_t oldSession = sessions.Begin();
    DriverVerdictRequest oldRequest = sessions.Receive(99);
    sessions.End(oldSession);

    uint64_t id = 0;
    Require(!sessions.Inspect(oldRequest, id));
    sessions.Begin();
    Require(!sessions.Inspect(oldRequest, id));

    DriverVerdictSession other;
    other.Begin();
    DriverVerdictRequest request = sessions.Receive(99);
    Require(!other.Inspect(request, id));
    Require(sessions.Inspect(request, id));
    Require(sessions.Consume(request, id));
}

void TestInspectRejectsEmptyAndMovedRequests() {
    DriverVerdictSession sessions;
    sessions.Begin();
    DriverVerdictRequest empty;
    uint64_t id = 0;
    Require(!sessions.Inspect(empty, id));

    DriverVerdictRequest original = sessions.Receive(7);
    DriverVerdictRequest moved(std::move(original));
    Require(!sessions.Inspect(original, id));
    Require(sessions.Inspect(moved, id));
    Require(id == 7);
}

void TestRepeatedDriverNotificationsHaveSeparateRequests() {
    DriverVerdictSession sessions;
    sessions.Begin();

    DriverVerdictRequest first = sessions.Receive(5);
    DriverVerdictRequest second = sessions.Receive(5);
    uint64_t id = 0;
    Require(sessions.Consume(first, id));
    Require(sessions.Consume(second, id));
}

} // namespace

template <class T>
concept ExposesExternalConnectionId = requires(const T& request) {
    request.externalConnectionId();
};

static_assert(!ExposesExternalConnectionId<DriverVerdictRequest>);
static_assert(!std::is_copy_constructible_v<DriverVerdictRequest>);
static_assert(!std::is_copy_assignable_v<DriverVerdictRequest>);
static_assert(std::is_nothrow_move_constructible_v<DriverVerdictRequest>);
static_assert(!std::is_copy_constructible_v<DriverVerdictSession>);
static_assert(!std::is_move_constructible_v<DriverVerdictSession>);

int main() {
    TestRequestExistsOnlyInsideSession();
    TestZeroExternalIdIsValid();
    TestMoveTransfersSingleObligation();
    TestRequestCanBeConsumedOnlyOnce();
    TestEndedSessionRejectsDelayedAnswer();
    TestOldSessionCannotAnswerNewDriver();
    TestLateDisconnectDoesNotEndNewSession();
    TestRequestBelongsToIssuingGate();
    TestInspectPreservesObligation();
    TestInspectAcceptsZeroExternalId();
    TestInspectRejectsStaleAndForeignRequests();
    TestInspectRejectsEmptyAndMovedRequests();
    TestRepeatedDriverNotificationsHaveSeparateRequests();
    return 0;
}
