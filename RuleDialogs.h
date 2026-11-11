#pragma once
#include "Rules.h"

namespace RuleDialogs {

// Выбор протокола: любой номер 0..255 либо «любой протокол» (anyProto = true,
// условие CondProto снимается). Известные номера выбираются из списка.
bool ChooseProtocol(HWND owner, HINSTANCE inst, Proto& proto, bool& anyProto);

bool ChooseAddresses(HWND owner, HINSTANCE inst, const wchar_t* title,
                     std::vector<AddrItem>& items);
bool ChoosePorts(HWND owner, HINSTANCE inst, const wchar_t* title,
                 std::vector<PortItem>& items);

// Перегрузки под заголовки из ресурсов: строка живёт до конца выражения,
// а диалог не переживает свой вызов
inline bool ChooseAddresses(HWND owner, HINSTANCE inst, const std::wstring& title,
                            std::vector<AddrItem>& items) {
    return ChooseAddresses(owner, inst, title.c_str(), items);
}
inline bool ChoosePorts(HWND owner, HINSTANCE inst, const std::wstring& title,
                        std::vector<PortItem>& items) {
    return ChoosePorts(owner, inst, title.c_str(), items);
}
// v6 задаёт таблицу типов: ICMPv4 либо ICMPv6
bool ChooseIcmpTypes(HWND owner, HINSTANCE inst, bool v6,
                     std::vector<IcmpTypeItem>& items);
// Выбор сервисов Windows: список установленных с фильтром и отметками.
// Пустой результат допустим и означает «любой сервис».
bool ChooseServices(HWND owner, HINSTANCE inst, std::vector<ServiceItem>& items);
// Точное имя подключения; можно указать отсутствующий сейчас интерфейс.
bool ChooseInterface(HWND owner, HINSTANCE inst, std::wstring& name);
// Все отмеченные биты должны присутствовать в исходной маске WFP события.
bool ChooseWfpFlags(HWND owner, HINSTANCE inst, uint32_t& flags);

// Показать ошибку записи один раз для версии правил; true — сообщение показано.
// Тесты подставляют showMessage, чтобы проверить предупреждение без создания окна.
bool ShowSaveError(HWND owner, const RuleStore& store, uint64_t& reportedVersion,
                   decltype(&MessageBoxW) showMessage = MessageBoxW);

// Диалогов выбора направления и действия нет: у каждого всего два значения,
// щелчок по ссылке в расшифровке правила сразу переключает их.

// IPv6-адрес с необязательным префиксом 0..128; при ошибке out не меняется.
bool ParseIpv6Address(const std::wstring& text, AddrItem& out);

std::wstring PortsToText(const std::vector<PortItem>& v);
bool ParsePortList(const std::wstring& text, std::vector<PortItem>& out, std::wstring& err);
std::wstring IcmpTypesToText(const std::vector<IcmpTypeItem>& v);
bool ParseIcmpTypeList(const std::wstring& text, std::vector<IcmpTypeItem>& out,
                       std::wstring& err);
std::wstring ServicesToText(const std::vector<ServiceItem>& v);
// Имена сервисов через запятую. Позволяет указать сервис, которого на этом
// компьютере нет (правило переносится между машинами).
bool ParseServiceList(const std::wstring& text, std::vector<ServiceItem>& out,
                      std::wstring& err);

// Обработка щелчка по ссылке в расшифровке правила
bool FollowLink(HWND owner, HINSTANCE inst, Rule& r, const wchar_t* linkId);

} // namespace RuleDialogs