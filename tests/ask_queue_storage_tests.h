struct AskQueueTestAccess {
    static void AddStale(AskQueue& queue, uint64_t groupId) {
        const AskRequestId id{UINT64_MAX, groupId};
        queue.in_.insert(id);
        queue.q_.push_back({id, 0});
    }

    static void TestStorage() {
        DriverVerdictSession session;
        captureSession = &session;
        sentVerdicts.clear();
        Ingest& ingest = Ingest::Instance();
        IngestTestAccess::ResetSessionState(ingest);
        RuleStore rules;
        ingest.Attach(&rules, nullptr);
        ingest.BeginDriverSession(session.Begin());
        const AskRequest seed = Request(L"C:\\Apps\\queue-storage.exe");
        const AskRequestId id = IngestTestAccess::Park(ingest, session, seed, {800});
        AskRequest request;
        Check(ingest.GetPending(id, request), "queue storage fixture lost its pending group");
        for (unsigned mode = 0; mode < 3; ++mode) {
            AskQueue queue;
            if (mode == 2) {
                queue.in_.reserve(20000);
                AddStale(queue, 1);
            } else {
                for (uint64_t i = 1; i <= 20000; ++i) AddStale(queue, i);
            }
            const size_t peak = queue.in_.bucket_count();
            Check(queue.Push(request), "live pending could not enter the queue");
            queue.Postpone(request);
            if (mode == 0) {
                queue.Prune();
                Check(queue.size() == 1 && queue.held() == 1 &&
                      queue.in_.bucket_count() < peak / 8 && !queue.Push(request),
                      "queue pruning retained peak storage or lost a held/deduplicated request");
                const size_t stable = queue.in_.bucket_count();
                for (unsigned pass = 0; pass < 100; ++pass) queue.Prune();
                Check(queue.in_.bucket_count() == stable,
                      "stable queue maintenance repeatedly reallocated index buckets");
            } else if (mode == 2) {
                queue.Discard({UINT64_MAX, 1});
                Check(queue.size() == 1 && queue.held() == 1 &&
                      queue.in_.bucket_count() < peak / 8,
                      "discard retained peak index storage or changed another request");
                queue.Discard(id);
            }
            if (mode != 2) {
                queue.MakeAllReady();
                AskRequest shown;
                Check(queue.Pop(shown) && shown.id == id,
                      "queue compaction lost the remaining live request");
            }
            AskRequest empty;
            Check(queue.empty() && queue.in_.empty() && queue.in_.bucket_count() <= 8 &&
                  !queue.Pop(empty) && ingest.IsPending(id) && ingest.waiting() == 1 &&
                  sentVerdicts.empty(),
                  "drained queue retained storage or changed a driver obligation");
        }
        // Даже очередь без живого запроса освобождается через неуспешный Pop.
        AskQueue stale;
        for (uint64_t i = 1; i <= 20000; ++i) AddStale(stale, i);
        AskRequest empty;
        Check(!stale.Pop(empty) && stale.empty() && stale.in_.empty() &&
              stale.in_.bucket_count() <= 8 && ingest.IsPending(id),
              "unsuccessful Pop retained stale queue buckets or changed pending");
        ingest.EndDriverSession(session.End());
        captureSession = nullptr;
    }
};
