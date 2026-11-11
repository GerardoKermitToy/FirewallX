#include <windows.h>
#include <winioctl.h>
#include <winsvc.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "ServiceControl.h"
#include "TrafficAttributionOptions.h"

namespace {

void Check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

struct MockDriver {
    std::array<uint8_t, 4> version{3, 0, 0, 0};
    DWORD versionSize = 4;
    DWORD versionError = ERROR_SUCCESS;
    DWORD serviceState = SERVICE_STOPPED;
    bool pending = false;
    bool validQuery = false;
    unsigned queries = 0;
    unsigned shutdowns = 0;
    unsigned processStarts = 0;
    unsigned processWrites = 0;
    DWORD processError = ERROR_SUCCESS;
    bool validStart = true;
    HANDLE device = INVALID_HANDLE_VALUE;
} g_mock;

// Подмены действуют только при компиляции header-only KextClient в этом тесте.
// SCM, реальный драйвер и его параметры реестра не затрагиваются.
SC_HANDLE MockOpenSCManagerW(LPCWSTR, LPCWSTR, DWORD) {
    return reinterpret_cast<SC_HANDLE>(static_cast<uintptr_t>(1));
}
SC_HANDLE MockOpenServiceW(SC_HANDLE, LPCWSTR, DWORD) {
    return reinterpret_cast<SC_HANDLE>(static_cast<uintptr_t>(2));
}
BOOL MockCloseServiceHandle(SC_HANDLE) { return TRUE; }
BOOL MockDeleteService(SC_HANDLE) { return TRUE; }
BOOL MockQueryServiceStatusEx(SC_HANDLE, SC_STATUS_TYPE, LPBYTE data,
                              DWORD, LPDWORD needed) {
    auto* status = reinterpret_cast<SERVICE_STATUS_PROCESS*>(data);
    *status = {};
    status->dwCurrentState = g_mock.serviceState;
    *needed = sizeof(*status);
    return TRUE;
}
BOOL MockStartServiceW(SC_HANDLE, DWORD, LPCWSTR*) {
    g_mock.serviceState = SERVICE_RUNNING;
    return TRUE;
}
BOOL MockControlService(SC_HANDLE, DWORD, LPSERVICE_STATUS status) {
    *status = {};
    status->dwCurrentState = g_mock.serviceState = SERVICE_STOPPED;
    return TRUE;
}
HANDLE MockCreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES,
                       DWORD, DWORD, HANDLE) {
    g_mock.device = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    return g_mock.device ? g_mock.device : INVALID_HANDLE_VALUE;
}
BOOL MockDeviceIoControl(HANDLE, DWORD code, LPVOID input, DWORD inputSize,
                         LPVOID output, DWORD outputSize, LPDWORD,
                         LPOVERLAPPED overlapped) {
    if (code == 0x9C40E000) {
        ++g_mock.queries;
        g_mock.validQuery = input == nullptr && inputSize == 0 &&
                            output != nullptr && outputSize == 4;
        if (g_mock.versionError != ERROR_SUCCESS) {
            SetLastError(g_mock.versionError);
            return FALSE;
        }
        std::memcpy(output, g_mock.version.data(),
                    (std::min)(outputSize, DWORD{4}));
        overlapped->InternalHigh = g_mock.versionSize;
    } else if (code == 0x9C40E004) {
        ++g_mock.shutdowns;
        overlapped->InternalHigh = 0;
    } else if (code == 0x9C40E00C) {
        ++g_mock.processStarts;
        g_mock.validStart &= input == nullptr && inputSize == 0 &&
                             output == nullptr && outputSize == 0;
        if (g_mock.processError != ERROR_SUCCESS) {
            SetLastError(g_mock.processError);
            return FALSE;
        }
        overlapped->InternalHigh = 0;
    } else {
        SetLastError(ERROR_INVALID_FUNCTION);
        return FALSE;
    }
    overlapped->Internal = 0;
    if (g_mock.pending) {
        SetLastError(ERROR_IO_PENDING);
        return FALSE;
    }
    return TRUE;
}
BOOL MockWriteFile(HANDLE, LPCVOID data, DWORD size, LPDWORD, LPOVERLAPPED overlapped) {
    ++g_mock.processWrites;
    g_mock.validStart &= size == 1 && data && *static_cast<const uint8_t*>(data) == 9;
    if (g_mock.processError != ERROR_SUCCESS) {
        SetLastError(g_mock.processError);
        return FALSE;
    }
    overlapped->Internal = 0;
    overlapped->InternalHigh = size;
    if (g_mock.pending) {
        SetLastError(ERROR_IO_PENDING);
        return FALSE;
    }
    return TRUE;
}
BOOL MockGetOverlappedResult(HANDLE, LPOVERLAPPED overlapped,
                             LPDWORD transferred, BOOL) {
    *transferred = static_cast<DWORD>(overlapped->InternalHigh);
    return TRUE;
}

} // namespace

#define OpenSCManagerW MockOpenSCManagerW
#define OpenServiceW MockOpenServiceW
#define CloseServiceHandle MockCloseServiceHandle
#define DeleteService MockDeleteService
#define QueryServiceStatusEx MockQueryServiceStatusEx
#define StartServiceW MockStartServiceW
#define ControlService MockControlService
#define CreateFileW MockCreateFileW
#define WriteFile MockWriteFile
#define DeviceIoControl MockDeviceIoControl
#define GetOverlappedResult MockGetOverlappedResult
#include "PortmasterKextClient.hpp"
#undef OpenSCManagerW
#undef OpenServiceW
#undef CloseServiceHandle
#undef DeleteService
#undef QueryServiceStatusEx
#undef StartServiceW
#undef ControlService
#undef CreateFileW
#undef WriteFile
#undef DeviceIoControl
#undef GetOverlappedResult

#include "duplex_pipe/pipe_transport.h"

namespace FirewallX {
Mode g_runMode = Mode::Desktop;
}
namespace TrafficAttributionOptions {
DWORD ApplySaved() { return ERROR_SUCCESS; }
}

namespace {

void CheckOpen(std::array<uint8_t, 4> version, DWORD size, DWORD error,
               bool pending, DWORD expected) {
    g_mock = {};
    g_mock.version = version;
    g_mock.versionSize = size;
    g_mock.versionError = error;
    g_mock.pending = pending;
    pmkext::KextClient client;
    const bool opened = client.open();
    Check(opened == (expected == ERROR_SUCCESS), "неверный результат проверки версии драйвера");
    Check(g_mock.queries == 1 && g_mock.validQuery, "версия не запрошена ровно одним IOCTL_VERSION");
    if (opened) {
        Check(g_mock.processStarts == 0 && g_mock.processWrites == 0,
              "open самовольно запустил сбор процессов");
        Check(client.open() && g_mock.queries == 1, "повторный open изменил готовую сессию");
        client.close();
        Check(g_mock.shutdowns == 1, "совместимая сессия не закрыта штатно");
    } else {
        Check(!client.isOpen() && client.lastError() == expected,
              "ошибка версии потеряна либо устройство оставлено открытым");
        Check(!client.startReadLoop(), "reader запущен для несовместимого драйвера");
        DWORD flags = 0;
        Check(!GetHandleInformation(g_mock.device, &flags), "дескриптор отвергнутого драйвера не закрыт");
        client.close();
        Check(g_mock.shutdowns == 0, "несовместимому драйверу отправлена команда Shutdown");
    }
}

void TestDriverVersions() {
    for (const auto mode : {FirewallX::Mode::Desktop, FirewallX::Mode::Service}) {
        FirewallX::g_runMode = mode;
        for (const bool pending : {false, true}) {
            for (const auto version : {
                    std::array<uint8_t, 4>{3, 0, 0, 0}, {3, 0, 0, 1}, {3, 0, 1, 0},
                    {3, 1, 0, 0}, {3, 255, 255, 255}, {4, 0, 0, 0},
                    {255, 255, 255, 255}}) {
                CheckOpen(version, 4, ERROR_SUCCESS, pending, ERROR_SUCCESS);
            }
            for (const auto version : {
                    std::array<uint8_t, 4>{0, 0, 0, 0}, {0, 255, 255, 255},
                    {1, 0, 0, 0}, {2, 0, 0, 0}, {2, 255, 255, 255}}) {
                CheckOpen(version, 4, ERROR_SUCCESS, pending, ERROR_REVISION_MISMATCH);
            }
            for (const DWORD size : {DWORD{0}, DWORD{1}, DWORD{3}, DWORD{5}})
                CheckOpen({3, 0, 0, 0}, size, ERROR_SUCCESS, pending, ERROR_INVALID_DATA);
        }
        for (const DWORD error : {DWORD{ERROR_INVALID_FUNCTION}, DWORD{ERROR_ACCESS_DENIED}})
            CheckOpen({3, 0, 0, 0}, 4, error, false, error);
    }
    FirewallX::g_runMode = FirewallX::Mode::Desktop;

    // После отказа тот же объект может открыть уже совместимый драйвер.
    g_mock = {};
    g_mock.version = {2, 0, 0, 0};
    pmkext::KextClient client;
    Check(!client.open(), "старый драйвер принят перед повторным подключением");
    g_mock.version = {3, 0, 0, 0};
    Check(client.open() && g_mock.queries == 2, "повторное открытие после исправления версии не удалось");
}

void TestProcessControl() {
    for (const bool pending : {false, true}) {
        g_mock = {};
        g_mock.pending = pending;
        pmkext::KextClient client;
        Check(client.open(), "не удалось открыть mock-устройство");
        const pmkext::ProcessCreated entry{0, 0};
        client.dispatchOne(pmkext::InfoType::ProcessCreated,
                           reinterpret_cast<const uint8_t*>(&entry), sizeof(entry));
        for (unsigned i = 0; i < 2; ++i) {
            Check(client.ioctlStartProcessMonitoring(), "start IOCTL не прошёл");
            Check(client.sendStartProcessMonitoring(), "start write не прошёл");
        }
        Check(g_mock.processStarts == 2 && g_mock.processWrites == 2 && g_mock.validStart,
              "неверный IOCTL, payload или номер write-команды");
        Check(client.processes().size() == 1, "повторный запрос очистил локальные события");
        client.setProcessEventsEnabled(false);
        Check(!client.processEventsEnabled() && client.processes().size() == 0,
              "подключение клиента не очистило таблицу службы");
        Check(client.ioctlStartProcessMonitoring() && client.sendStartProcessMonitoring(),
              "запрос клиента в режиме пересылки не прошёл");
        client.dispatchOne(pmkext::InfoType::ProcessCreated,
                           reinterpret_cast<const uint8_t*>(&entry), sizeof(entry));
        Check(!client.processEventsEnabled() && client.processes().size() == 0,
              "запрос снимка клиента включил локальный сбор службы");
        client.setProcessEventsEnabled(true);
        Check(client.processEventsEnabled() && client.processes().size() == 0 &&
              client.ioctlStartProcessMonitoring() && g_mock.processStarts == 4,
              "локальный сбор не перезапущен с пустой таблицы новым IOCTL");
        client.dispatchOne(pmkext::InfoType::ProcessCreated,
                           reinterpret_cast<const uint8_t*>(&entry), sizeof(entry));
        Check(client.processes().size() == 1, "новый локальный снимок не сохранён");
        g_mock.processError = ERROR_ACCESS_DENIED;
        Check(!client.ioctlStartProcessMonitoring() && client.lastError() == ERROR_ACCESS_DENIED,
              "ошибка start IOCTL потеряна");
        Check(!client.sendStartProcessMonitoring() && client.lastError() == ERROR_ACCESS_DENIED,
              "ошибка start write потеряна");
        client.close();
        Check(client.processes().size() == 0, "close не очистил таблицу процессов");
        Check(!client.ioctlStartProcessMonitoring() && client.lastError() == ERROR_INVALID_HANDLE,
              "start IOCTL выполнен без устройства");
        Check(!client.sendStartProcessMonitoring() && client.lastError() == ERROR_INVALID_HANDLE,
              "start write выполнен без устройства");
    }
}

pipe_transport::UniqueHandle CreateServer(const std::wstring& name) {
    pipe_transport::UniqueHandle pipe(CreateNamedPipeW(
        name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1, 64 * 1024, 64 * 1024, 0, nullptr));
    Check(pipe.IsValid(), "не удалось создать тестовый pipe");
    return pipe;
}

pipe_transport::UniqueHandle OpenClient(const std::wstring& name) {
    pipe_transport::UniqueHandle pipe(CreateFileW(
        name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED, nullptr));
    Check(pipe.IsValid(), "не удалось открыть тестовый pipe");
    DWORD mode = PIPE_READMODE_MESSAGE;
    Check(SetNamedPipeHandleState(pipe.Get(), &mode, nullptr, nullptr) != FALSE,
          "не удалось включить message mode тестового pipe");
    return pipe;
}

struct PipePair {
    static inline unsigned sequence = 0;
    std::wstring name = L"\\\\.\\pipe\\FirewallX.ApiCompatibility." +
        std::to_wstring(GetCurrentProcessId()) + L"." + std::to_wstring(++sequence);
    pipe_transport::Connection server{CreateServer(name)};
    pipe_transport::Connection client{OpenClient(name)};

    PipePair() {
        Check(pipe_transport::ConnectNamedPipeCancelable(server.Pipe(), server.CancelEvent()) == ERROR_SUCCESS,
              "не удалось соединить тестовый pipe");
    }
};

std::array<byte, 12> Header(uint16_t version, byte type) {
    return {0x50, 0x49, 0x50, 0x45, static_cast<byte>(version),
            static_cast<byte>(version >> 8), type, 0, 0, 0, 0, 0};
}

void CheckRaw(pipe_transport::Connection& sender, pipe_transport::Connection& receiver,
              const byte* data, unsigned long size) {
    Check(pipe_transport::WriteRaw(sender, data, size, 1000) == ERROR_SUCCESS,
          "raw-сообщение не отправлено");
    pipe_transport::RawMessage message;
    Check(pipe_transport::ReadRaw(receiver, message, 1000) == ERROR_SUCCESS,
          "raw-сообщение не получено");
    Check(message.Size() == size && std::memcmp(message.Data(), data, size) == 0,
          "pipe изменил wire-ABI или добавил оболочку");
}

void TestHandshakeVersion() {
    using pipe_transport::HandshakeType;
    for (const auto type : {HandshakeType::Ready, HandshakeType::Accepted, HandshakeType::Rejected}) {
        PipePair pipes;
        Check(pipe_transport::WriteHandshake(pipes.server, type, 1000) == ERROR_SUCCESS,
              "рукопожатие не отправлено");
        pipe_transport::RawMessage message;
        const auto expected = Header(3, static_cast<byte>(type));
        Check(pipe_transport::ReadRaw(pipes.client, message, 1000) == ERROR_SUCCESS &&
              message.Size() == expected.size() &&
              std::memcmp(message.Data(), expected.data(), expected.size()) == 0,
              "рукопожатие не объявляет совместимость с API v3");
    }
    for (const uint16_t version : {uint16_t{0}, uint16_t{1}, uint16_t{2}, uint16_t{4}, uint16_t{65535}}) {
        for (const byte type : {byte{1}, byte{3}}) {
            PipePair pipes;
            const auto header = Header(version, type);
            Check(pipe_transport::WriteRaw(pipes.server, header.data(),
                                          static_cast<unsigned long>(header.size()), 1000) == ERROR_SUCCESS,
                  "несовместимое рукопожатие не отправлено");
            HandshakeType received = HandshakeType::Rejected;
            Check(pipe_transport::ReadHandshake(pipes.client, received, 1000) == ERROR_REVISION_MISMATCH,
                  "несовместимая версия pipe не отклонена явно");
            Check(!pipes.client.IsActive() && received == HandshakeType::Rejected,
                  "несовместимая сессия осталась активной");
        }
    }
    for (const unsigned field : {0U, 6U, 8U}) {
        PipePair pipes;
        auto header = Header(3, 1);
        header[field] = 0xFF;
        Check(pipe_transport::WriteRaw(pipes.server, header.data(),
                                      static_cast<unsigned long>(header.size()), 1000) == ERROR_SUCCESS,
              "повреждённое рукопожатие не отправлено");
        HandshakeType received = HandshakeType::Rejected;
        Check(pipe_transport::ReadHandshake(pipes.client, received, 1000) == ERROR_INVALID_DATA,
              "повреждённое рукопожатие принято");
    }
}

void TestRawWireAbi() {
    using pipe_transport::HandshakeType;
    PipePair pipes;
    HandshakeType type = HandshakeType::Rejected;
    Check(pipe_transport::WriteHandshake(pipes.server, HandshakeType::Ready, 1000) == ERROR_SUCCESS &&
          pipe_transport::ReadHandshake(pipes.client, type, 1000) == ERROR_SUCCESS && type == HandshakeType::Ready,
          "совместимый клиент не принял Ready");
    Check(pipe_transport::WriteHandshake(pipes.client, HandshakeType::Accepted, 1000) == ERROR_SUCCESS &&
          pipe_transport::ReadHandshake(pipes.server, type, 1000) == ERROR_SUCCESS && type == HandshakeType::Accepted,
          "совместимая служба не приняла Accepted");

    // Полные записи драйвера строятся независимо от структур KextClient.
    for (const byte infoType : {byte{7}, byte{8}}) {
        const unsigned fixedSize = infoType == 7 ? 59 : 83;
        std::vector<byte> record{infoType, static_cast<byte>(fixedSize + 4), 0, 0, 0};
        for (unsigned i = 0; i < fixedSize - 4; ++i) record.push_back(static_cast<byte>(i + 1));
        record[5 + 40] = 1;
        record[5 + 41] = 17;
        record.back() = 3;
        record.insert(record.end(), {4, 0, 0, 0, 0xDE, 0xAD, 0xBE, 0xEF});
        CheckRaw(pipes.server, pipes.client, record.data(), static_cast<unsigned long>(record.size()));
    }
    const std::array<byte, 10> verdict{1, 8, 7, 6, 5, 4, 3, 2, 1, 3};
    CheckRaw(pipes.client, pipes.server, verdict.data(), static_cast<unsigned long>(verdict.size()));
    for (const byte infoType : {byte{9}, byte{10}}) {
        const byte payloadSize = infoType == 9 ? byte{32} : byte{16};
        std::vector<byte> record{infoType, payloadSize, 0, 0, 0};
        for (byte i = 0; i < payloadSize; ++i) record.push_back(i);
        CheckRaw(pipes.server, pipes.client, record.data(), static_cast<unsigned long>(record.size()));
    }
    const byte startProcesses = 9;
    CheckRaw(pipes.client, pipes.server, &startProcesses, 1);
    const byte getLogs = 5;
    CheckRaw(pipes.client, pipes.server, &getLogs, 1);
}

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc == 1 || std::strcmp(argv[1], "--driver") == 0) {
            TestDriverVersions();
            TestProcessControl();
        }
        if (argc == 1 || std::strcmp(argv[1], "--pipe") == 0) {
            TestHandshakeVersion();
            TestRawWireAbi();
        }
        std::cout << "API compatibility tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
