#include "NdisBindingAsync.h"
#include <new>
#include <utility>

namespace ndis_binding::detail {

struct TargetResolver::Work {
    std::atomic<bool> stopped{false};
    Query query;
    Targets targets;
    HRESULT status = E_PENDING;
    HANDLE done = nullptr, thread = nullptr;
    DWORD threadId = 0;
    explicit Work(Query function) : query(std::move(function)) {
        done = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!done) throw Error{ HRESULT_FROM_WIN32(GetLastError()) };
    }
    ~Work() {
        if (thread) CloseHandle(thread);
        if (done) CloseHandle(done);
    }
    void Cancel() noexcept {
        stopped.store(true);
        // Это дополнение к ограниченному ожиданию, а не гарантия отмены вызова NetCfg.
        CoCancelCall(threadId, 0);
    }
};

DWORD WINAPI TargetResolver::Worker(void* context) noexcept {
    std::unique_ptr<std::shared_ptr<Work>> argument(static_cast<std::shared_ptr<Work>*>(context));
    const auto work = *argument;
    const HRESULT initialized = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    bool cancellation = false;
    try {
        Check(initialized);
        cancellation = SUCCEEDED(CoEnableCallCancellation(nullptr));
        if (work->stopped.load()) throw Error{ HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED) };
        work->targets = work->query(work->stopped);
        work->status = S_OK;
    } catch (const Error& error) {
        work->status = error.status;
    } catch (const std::bad_alloc&) {
        work->status = E_OUTOFMEMORY;
    } catch (...) {
        work->status = E_UNEXPECTED;
    }
    if (cancellation) CoDisableCallCancellation(nullptr);
    if (SUCCEEDED(initialized)) CoUninitialize();
    SetEvent(work->done);
    return 0;
}

Targets TargetResolver::Resolve(const std::atomic<bool>& stopped, Query query, DWORD timeoutMs) {
    if (stopped.load()) throw Error{ HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED) };
    if (!query || !timeoutMs || timeoutMs == INFINITE) throw Error{ E_INVALIDARG };
    std::shared_ptr<Work> work;
    {
        std::lock_guard guard(lock_);
        // Зависший read-only запрос не порождает новые потоки на каждом retry.
        if (active_) {
            const DWORD state = WaitForSingleObject(active_->done, 0);
            if (state == WAIT_TIMEOUT) throw Error{ HRESULT_FROM_WIN32(ERROR_BUSY) };
            if (state != WAIT_OBJECT_0) throw Error{ HRESULT_FROM_WIN32(GetLastError()) };
        }
        work = std::make_shared<Work>(std::move(query));
        auto argument = std::make_unique<std::shared_ptr<Work>>(work);
        work->thread = CreateThread(nullptr, 0, Worker, argument.get(), 0, &work->threadId);
        if (!work->thread) throw Error{ HRESULT_FROM_WIN32(GetLastError()) };
        argument.release();
        active_ = work;
    }
    const auto started = GetTickCount64();
    for (;;) {
        if (stopped.load()) {
            work->Cancel();
            throw Error{ HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED) };
        }
        const auto elapsed = GetTickCount64() - started;
        if (elapsed >= timeoutMs) {
            work->Cancel();
            throw Error{ HRESULT_FROM_WIN32(ERROR_TIMEOUT) };
        }
        const DWORD remaining = timeoutMs - static_cast<DWORD>(elapsed);
        // Проверяем отмену не чаще раза за 250 мс; завершившийся запрос будит сразу.
        const DWORD result = WaitForSingleObject(work->done, remaining < 250 ? remaining : 250);
        if (result == WAIT_TIMEOUT) continue;
        if (result != WAIT_OBJECT_0) {
            const auto error = HRESULT_FROM_WIN32(GetLastError());
            work->Cancel();
            throw Error{ error };
        }
        {
            std::lock_guard guard(lock_);
            if (active_ == work) active_.reset();
        }
        Check(work->status);
        return work->targets;
    }
}

} // namespace ndis_binding::detail
