cmake_minimum_required(VERSION 3.25)

# Политика CMP0141 включена минимальной версией CMake: /Zi нужен и в Release.
set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT ProgramDatabase)

project(FirewallX LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "Firewall is a Windows-only project")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")

if(MSVC)
    # Компилятор MSVC собирает исходники проекта параллельно.
    add_compile_options("$<$<COMPILE_LANGUAGE:CXX>:/MP>")

    # Для сборки x64 разрешаем использование инструкций SSE4.2.
    if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC" AND CMAKE_CXX_COMPILER_ARCHITECTURE_ID STREQUAL "x64")
        add_compile_options("$<$<COMPILE_LANGUAGE:CXX>:/arch:SSE4.2>")
    endif()

    # Полный PDB без FASTLINK, с сохранением оптимизаций Release.
    add_link_options(
        "$<$<CONFIG:Release>:/DEBUG:FULL>"
        "$<$<CONFIG:Release>:/OPT:REF>"
        "$<$<CONFIG:Release>:/OPT:ICF>"
    )

    # В exe записывается только имя PDB, без пути на машине сборки.
    # Для Visual Studio передаём % через свойство MSBuild, иначе CMake
    # удваивает их при экранировании и в exe остаются лишние символы %.
    if(CMAKE_GENERATOR MATCHES "^Visual Studio ")
        list(APPEND CMAKE_VS_GLOBALS "FirewallXPdbAltPath=%_PDB%")
        add_link_options("/PDBALTPATH:$(FirewallXPdbAltPath)")
    else()
        add_link_options(/PDBALTPATH:%_PDB%)
    endif()
endif()

# Импортируется только NSI-чтение; менять routepolicies разрешено лишь через netsh.
set(FIREWALLX_NSI_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/nsi.lib")
set(FIREWALLX_NSI_DEFINITION "${CMAKE_CURRENT_SOURCE_DIR}/nsi.def")
if(MSVC)
    if(CMAKE_CXX_COMPILER_ARCHITECTURE_ID STREQUAL "ARM64")
        set(FIREWALLX_NSI_MACHINE ARM64)
    elseif(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(FIREWALLX_NSI_MACHINE X64)
    else()
        message(FATAL_ERROR "The NSI route-policy query requires a 64-bit target.")
    endif()
    add_custom_command(OUTPUT "${FIREWALLX_NSI_LIBRARY}"
        COMMAND "${CMAKE_AR}" /nologo "/def:${FIREWALLX_NSI_DEFINITION}"
                "/machine:${FIREWALLX_NSI_MACHINE}" "/out:${FIREWALLX_NSI_LIBRARY}"
        DEPENDS "${FIREWALLX_NSI_DEFINITION}"
        BYPRODUCTS "${CMAKE_CURRENT_BINARY_DIR}/nsi.exp"
        VERBATIM)
else()
    if(NOT CMAKE_DLLTOOL OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
        message(FATAL_ERROR "Generating nsi.lib requires a 64-bit target and dlltool.")
    endif()
    add_custom_command(OUTPUT "${FIREWALLX_NSI_LIBRARY}"
        COMMAND "${CMAKE_DLLTOOL}" --input-def "${FIREWALLX_NSI_DEFINITION}"
                --output-lib "${FIREWALLX_NSI_LIBRARY}"
        DEPENDS "${FIREWALLX_NSI_DEFINITION}"
        VERBATIM)
endif()
add_custom_target(firewallx_nsi_library DEPENDS "${FIREWALLX_NSI_LIBRARY}")
add_library(firewallx_nsi_import STATIC IMPORTED)
set_target_properties(firewallx_nsi_import PROPERTIES
    IMPORTED_LOCATION "${FIREWALLX_NSI_LIBRARY}")
add_dependencies(firewallx_nsi_import firewallx_nsi_library)

# Общий источник IP-интерфейсов для продукта и потребителей макроадресов.
add_library(firewallx_network_interfaces STATIC
    network_interface_watcher.cpp network_interface_watcher.h
)
target_include_directories(firewallx_network_interfaces PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(firewallx_network_interfaces PUBLIC
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX
    _WIN32_WINNT=0x0A00 WINVER=0x0A00 NTDDI_VERSION=0x0A000010
)
target_link_libraries(firewallx_network_interfaces PUBLIC iphlpapi advapi32)
if(MSVC)
    target_compile_options(firewallx_network_interfaces PRIVATE /W4 /WX /permissive- /utf-8 /Zc:__cplusplus)
endif()

# Нативное восстановление привязки фильтра без установки службы и запуска shell.
add_library(firewallx_ndis_binding STATIC
    NdisBinding.cpp NdisBindingWindows.cpp
    NdisBindingConfig.cpp NdisBindingAddition.cpp NdisBindingPreferences.cpp
    NdisBindingAsync.cpp NdisBindingAsync.h
    NdisBindingProcess.cpp NdisBindingProcess.h
    NdisBinding.h NdisBindingPath.h
)
target_include_directories(firewallx_ndis_binding PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(firewallx_ndis_binding PUBLIC
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX
    _WIN32_WINNT=0x0A00 WINVER=0x0A00 NTDDI_VERSION=0x0A000010
)
target_link_libraries(firewallx_ndis_binding PUBLIC
    ole32 uuid advapi32 iphlpapi shell32 winsqlite3
)
if(MSVC)
    target_compile_options(firewallx_ndis_binding PRIVATE /W4 /WX /permissive- /utf-8 /Zc:__cplusplus)
endif()

# SystemInfo.h умышленно header-only: кеш системного каталога и проверки
# существования процесса живут в inline-функциях, отдельная единица
# трансляции им не нужна.
add_executable(FirewallX WIN32
    main.cpp
    Util.cpp
    TlsReassembly.cpp
    quic_sni.cpp
    quic_sni.hpp
    UiKit.cpp
    Settings.cpp
    StringRes.cpp
    UiLangSetting.cpp
    WfpOptions.cpp
    WfpAudit.cpp
    StartupOptions.cpp
    WindowsFirewallOptions.cpp
    TrafficAttributionOptions.cpp
    ProcessProtectionOptions.cpp
    FileSignature.cpp
    FileSignature.h
    ProcessCache.cpp
    ProcessIcon.cpp
    FlowStore.cpp
    Ingest.cpp
    FirewallPolicy.cpp
    FirewallPolicySetting.cpp
    ThreadSuspend.cpp
    Monitor.cpp
    OwnerLookup.cpp
    ConnKill.cpp
    TreeList.cpp
    Rules.cpp
    RuleDb.cpp
    RuleDialogs.cpp
    RuleEditor.cpp
    AppRulesEditor.cpp
    AllRulesWindow.cpp
    SettingsWindow.cpp
    DebugWindow.cpp
    AskQueue.cpp
    AskWindow.cpp
    RulePresets.cpp
    RuleGenerator.cpp
    RuleGenerator.h
    RulePresetsData.h
    RulePresetsResource.h
    MacroAddr.cpp
    ServiceControl.cpp
    ServiceInfo.cpp
    SingleInstance.cpp
    TrayIcon.cpp
    PortmasterKextClient.hpp
    ProcessEvents.h
    FirewallXNdisFilter.hpp
    NdisTransport.cpp
    NdisTransport.h
    VerdictSession.h
    duplex_pipe/duplex_pipe_client.cpp
    duplex_pipe/duplex_pipe_server.cpp
    duplex_pipe/pipe_transport.cpp
    pipe_support.cpp
    firewall.rc
)

# ---------------------------------------------------------------------------
# Зависимости компиляции ресурсов.
#
# firewall.rc подключает языковые файлы директивой #include, но сканер
# зависимостей их не видит: для .rc ninja получает «#deps 0». Из-за этого
# правка перевода НЕ вызывала пересборку ресурсов — сборка проходила успешно,
# а в exe оставались прежние строки. Ошибка молчаливая и обнаруживается только
# поиском по готовому файлу, поэтому список задаётся здесь явно.
#
# resource.h нужен и как зависимость: в нём номера идентификаторов, версия и
# FIREWALLX_PRODUCT.
# ---------------------------------------------------------------------------
set_property(SOURCE firewall.rc APPEND PROPERTY OBJECT_DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/resource.h
    ${CMAKE_CURRENT_SOURCE_DIR}/RulePresetsResource.h
    ${CMAKE_CURRENT_SOURCE_DIR}/RulePresets.rc
    ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_ru.rc
    ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_en.rc
    ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_kr.rc
    ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_zh.rc
    ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_uk.rc
    ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_de.rc
    ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_fr.rc
    ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_es.rc
    ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_ar.rc
    ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_hi.rc
    ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_lv.rc
    ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_lt.rc
    ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_et.rc
    ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_ro.rc
    ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_sv.rc
    ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_pl.rc
    ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_vi.rc
    ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_pt.rc
    ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_it.rc
    ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_fa.rc
    ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_ja.rc
    ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_tr.rc
    ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_id.rc
    ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_cs.rc
    ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_th.rc
    ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_pt_br.rc
    ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_zh_tw.rc
    ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_hu.rc
    ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_el.rc
    ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_nl.rc
    ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_bg.rc
    ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_da.rc
    ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_nb.rc
    ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_fi.rc
    ${CMAKE_CURRENT_SOURCE_DIR}/firewall_dialogs_ru.rc
    ${CMAKE_CURRENT_SOURCE_DIR}/firewall_dialogs_en.rc
    ${CMAKE_CURRENT_SOURCE_DIR}/firewall.ico
    ${CMAKE_CURRENT_SOURCE_DIR}/flags/flag_ru.ico
    ${CMAKE_CURRENT_SOURCE_DIR}/flags/flag_us.ico
    ${CMAKE_CURRENT_SOURCE_DIR}/flags/flag_kr.ico
    ${CMAKE_CURRENT_SOURCE_DIR}/flags/flag_zh.ico
    ${CMAKE_CURRENT_SOURCE_DIR}/flags/flag_uk.ico
    ${CMAKE_CURRENT_SOURCE_DIR}/flags/flag_de.ico
    ${CMAKE_CURRENT_SOURCE_DIR}/flags/flag_fr.ico
    ${CMAKE_CURRENT_SOURCE_DIR}/flags/flag_es.ico
    ${CMAKE_CURRENT_SOURCE_DIR}/flags/flag_sa.ico
    ${CMAKE_CURRENT_SOURCE_DIR}/flags/flag_in.ico
    ${CMAKE_CURRENT_SOURCE_DIR}/flags/flag_lv.ico
    ${CMAKE_CURRENT_SOURCE_DIR}/flags/flag_lt.ico
    ${CMAKE_CURRENT_SOURCE_DIR}/flags/flag_ee.ico
    ${CMAKE_CURRENT_SOURCE_DIR}/flags/flag_ro.ico
    ${CMAKE_CURRENT_SOURCE_DIR}/flags/flag_se.ico
    ${CMAKE_CURRENT_SOURCE_DIR}/flags/flag_pl.ico
    ${CMAKE_CURRENT_SOURCE_DIR}/flags/flag_vn.ico
    ${CMAKE_CURRENT_SOURCE_DIR}/flags/flag_pt.ico
    ${CMAKE_CURRENT_SOURCE_DIR}/flags/flag_it.ico
    ${CMAKE_CURRENT_SOURCE_DIR}/flags/flag_ir.ico
    ${CMAKE_CURRENT_SOURCE_DIR}/flags/flag_jp.ico
    ${CMAKE_CURRENT_SOURCE_DIR}/flags/flag_tr.ico
    ${CMAKE_CURRENT_SOURCE_DIR}/flags/flag_id.ico
    ${CMAKE_CURRENT_SOURCE_DIR}/flags/flag_cz.ico
    ${CMAKE_CURRENT_SOURCE_DIR}/flags/flag_th.ico
    ${CMAKE_CURRENT_SOURCE_DIR}/flags/flag_br.ico
    ${CMAKE_CURRENT_SOURCE_DIR}/flags/flag_tw.ico
    ${CMAKE_CURRENT_SOURCE_DIR}/flags/flag_hu.ico
    ${CMAKE_CURRENT_SOURCE_DIR}/flags/flag_gr.ico
    ${CMAKE_CURRENT_SOURCE_DIR}/flags/flag_nl.ico
    ${CMAKE_CURRENT_SOURCE_DIR}/flags/flag_bg.ico
    ${CMAKE_CURRENT_SOURCE_DIR}/flags/flag_dk.ico
    ${CMAKE_CURRENT_SOURCE_DIR}/flags/flag_no.ico
    ${CMAKE_CURRENT_SOURCE_DIR}/flags/flag_fi.ico
    ${CMAKE_CURRENT_SOURCE_DIR}/app.manifest
)
# SQLite берётся системный: заголовок <winsqlite/winsqlite3.h> и
# winsqlite3.lib лежат в Windows SDK, реализация — в winsqlite3.dll из
# состава Windows. Своя копия sqlite3.h/.lib не нужна.
target_include_directories(FirewallX PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_definitions(FirewallX PRIVATE
    UNICODE _UNICODE
    WIN32_LEAN_AND_MEAN NOMINMAX
    _WIN32_WINNT=0x0A00 WINVER=0x0A00 NTDDI_VERSION=0x0A000010
)

target_link_libraries(FirewallX PRIVATE
    firewallx_ndis_binding firewallx_network_interfaces firewallx_nsi_import
    winsqlite3
    fwpuclnt
    iphlpapi ws2_32 comctl32 uxtheme gdi32 user32 dwrite
    shell32 shlwapi ole32 oleaut32 taskschd uuid advapi32 comdlg32 ntdll bcrypt wintrust
    xmllite windowscodecs
)

if(MSVC)
    target_compile_options(FirewallX PRIVATE /W4 /permissive- /utf-8 /Zc:__cplusplus)
    target_link_options(FirewallX PRIVATE /MANIFEST:NO)
    set_property(DIRECTORY PROPERTY VS_STARTUP_PROJECT FirewallX)
else()
    set(CMAKE_RC_FLAGS "${CMAKE_RC_FLAGS} -c65001")
    target_compile_options(FirewallX PRIVATE -Wall -Wextra -municode)
    target_link_options(FirewallX PRIVATE -municode -static-libstdc++ -static-libgcc)
endif()

# Диагностическая утилита не входит в обычную сборку продукта.
option(FIREWALLX_BUILD_DIAGNOSTICS "Build TCP table diagnostic utility" OFF)
if(FIREWALLX_BUILD_DIAGNOSTICS)
    add_executable(dump_tcp_table dump_tcp_table.cpp)
    target_compile_definitions(dump_tcp_table PRIVATE
        UNICODE _UNICODE
        WIN32_LEAN_AND_MEAN NOMINMAX
    )
    target_link_libraries(dump_tcp_table PRIVATE iphlpapi ws2_32)
    if(MSVC)
        target_compile_options(dump_tcp_table PRIVATE /W4 /utf-8)
    endif()
endif()

# Регрессионные тесты собираются отдельными целями и не входят в обычную
# сборку продукта.
option(FIREWALLX_BUILD_TESTS "Build FirewallX regression tests" OFF)
if(FIREWALLX_BUILD_TESTS)
    enable_testing()

    add_executable(file_signature_tests tests/file_signature_tests.cpp FileSignature.cpp FileSignature.h)
    target_include_directories(file_signature_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_definitions(file_signature_tests PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX
        _WIN32_WINNT=0x0A00 WINVER=0x0A00)
    target_link_libraries(file_signature_tests PRIVATE wintrust)
    if(MSVC)
        target_compile_options(file_signature_tests PRIVATE /W4 /permissive- /utf-8 /Zc:__cplusplus)
    endif()
    add_test(NAME file_signature COMMAND file_signature_tests)
    set_tests_properties(file_signature PROPERTIES TIMEOUT 60)

    # Тест использует настоящий App, но не вызывает Init и не запускает драйвер.
    get_target_property(tray_storage_sources FirewallX SOURCES)
    list(REMOVE_ITEM tray_storage_sources main.cpp firewall.rc)
    add_executable(auto_rules_tests tests/auto_rules_tests.cpp
        ${tray_storage_sources} rules_matching_tests.rc)
    foreach(property INCLUDE_DIRECTORIES COMPILE_DEFINITIONS COMPILE_OPTIONS LINK_OPTIONS LINK_LIBRARIES)
        get_target_property(value FirewallX ${property})
        set_property(TARGET auto_rules_tests PROPERTY ${property} "${value}")
    endforeach()
    target_compile_definitions(auto_rules_tests PRIVATE FIREWALLX_TEST_VERDICTS)
    add_test(NAME auto_rules COMMAND auto_rules_tests)
    set_tests_properties(auto_rules PROPERTIES TIMEOUT 60 RESOURCE_LOCK firewallx_ui)

    add_executable(tray_storage_tests
        tests/tray_storage_tests.cpp tests/debug_window_tests.cpp
        tests/settings_ndis_tests.cpp
        ${tray_storage_sources} rules_matching_tests.rc)
    foreach(property INCLUDE_DIRECTORIES COMPILE_DEFINITIONS COMPILE_OPTIONS LINK_OPTIONS LINK_LIBRARIES)
        get_target_property(value FirewallX ${property})
        set_property(TARGET tray_storage_tests PROPERTY ${property} "${value}")
    endforeach()
    add_test(NAME tray_storage COMMAND tray_storage_tests)
    set_tests_properties(tray_storage PROPERTIES TIMEOUT 60 RESOURCE_LOCK firewallx_ui)

    add_executable(generation_cache_tests tests/generation_cache_tests.cpp)
    target_include_directories(generation_cache_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    if(MSVC)
        target_compile_options(generation_cache_tests PRIVATE /W4 /permissive- /utf-8 /Zc:__cplusplus)
    else()
        target_compile_options(generation_cache_tests PRIVATE -Wall -Wextra)
    endif()
    add_test(NAME generation_cache COMMAND generation_cache_tests)
    set_tests_properties(generation_cache PROPERTIES TIMEOUT 60)

    add_executable(text_width_cache_tests tests/text_width_cache_tests.cpp)
    target_include_directories(text_width_cache_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    if(MSVC)
        target_compile_options(text_width_cache_tests PRIVATE /W4 /permissive- /utf-8 /Zc:__cplusplus)
    else()
        target_compile_options(text_width_cache_tests PRIVATE -Wall -Wextra)
    endif()
    add_test(NAME text_width_cache COMMAND text_width_cache_tests)
    set_tests_properties(text_width_cache PROPERTIES TIMEOUT 60)

    add_executable(tree_row_plan_tests tests/tree_row_plan_tests.cpp)
    target_include_directories(tree_row_plan_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    if(MSVC)
        target_compile_options(tree_row_plan_tests PRIVATE /W4 /permissive- /utf-8 /Zc:__cplusplus)
    else()
        target_compile_options(tree_row_plan_tests PRIVATE -Wall -Wextra)
    endif()
    add_test(NAME tree_row_plan COMMAND tree_row_plan_tests)
    set_tests_properties(tree_row_plan PROPERTIES TIMEOUT 60)

    add_executable(block_queue_tests tests/block_queue_tests.cpp)
    target_include_directories(block_queue_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    if(MSVC)
        target_compile_options(block_queue_tests PRIVATE /W4 /permissive- /utf-8 /Zc:__cplusplus)
    else()
        target_compile_options(block_queue_tests PRIVATE -Wall -Wextra)
    endif()
    add_test(NAME block_queue COMMAND block_queue_tests)
    set_tests_properties(block_queue PROPERTIES TIMEOUT 60)

    add_executable(process_cache_tests
        tests/process_cache_tests.cpp
        ProcessCache.cpp
        ProcessIcon.cpp
        StringRes.cpp
        rules_matching_tests.rc
    )
    target_include_directories(process_cache_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_definitions(process_cache_tests PRIVATE
        UNICODE _UNICODE
        WIN32_LEAN_AND_MEAN NOMINMAX
        _WIN32_WINNT=0x0A00 WINVER=0x0A00 NTDDI_VERSION=0x0A000010
        FIREWALLX_TEST_PROCESS_CACHE
    )
    target_link_libraries(process_cache_tests PRIVATE user32 gdi32 shell32 shlwapi ole32 xmllite windowscodecs)
    if(MSVC)
        target_compile_options(process_cache_tests PRIVATE /W4 /permissive- /utf-8 /Zc:__cplusplus)
        target_link_options(process_cache_tests PRIVATE /MANIFEST:NO)
    else()
        target_compile_options(process_cache_tests PRIVATE -Wall -Wextra)
    endif()
    add_test(NAME process_cache COMMAND process_cache_tests)
    set_tests_properties(process_cache PROPERTIES TIMEOUT 60)

    add_executable(runtime_buffer_tests
        tests/runtime_buffer_tests.cpp
        StringRes.cpp
        rules_matching_tests.rc
    )
    target_include_directories(runtime_buffer_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_definitions(runtime_buffer_tests PRIVATE
        UNICODE _UNICODE
        WIN32_LEAN_AND_MEAN NOMINMAX
        _WIN32_WINNT=0x0A00 WINVER=0x0A00 NTDDI_VERSION=0x0A000010
    )
    target_link_libraries(runtime_buffer_tests PRIVATE user32 advapi32)
    if(MSVC)
        target_compile_options(runtime_buffer_tests PRIVATE /W4 /permissive- /utf-8 /Zc:__cplusplus)
        target_link_options(runtime_buffer_tests PRIVATE /MANIFEST:NO)
    else()
        target_compile_options(runtime_buffer_tests PRIVATE -Wall -Wextra)
    endif()
    add_test(NAME runtime_buffer COMMAND runtime_buffer_tests)
    set_tests_properties(runtime_buffer PROPERTIES TIMEOUT 60)

    add_executable(ui_layout_tests
        tests/ui_layout_tests.cpp
        UiKit.cpp
        ProcessIcon.cpp
        TreeList.cpp
        Settings.cpp
        Util.cpp
        TlsReassembly.cpp
        StringRes.cpp
        rules_matching_tests.rc
    )
    target_include_directories(ui_layout_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_definitions(ui_layout_tests PRIVATE
        UNICODE _UNICODE
        WIN32_LEAN_AND_MEAN NOMINMAX
        _WIN32_WINNT=0x0A00 WINVER=0x0A00 NTDDI_VERSION=0x0A000010
    )
    target_link_libraries(ui_layout_tests PRIVATE
        winsqlite3
        iphlpapi ws2_32 comctl32 uxtheme gdi32 user32 dwrite
        shell32 shlwapi ole32 advapi32 comdlg32
        xmllite windowscodecs
    )
    if(MSVC)
        target_compile_options(ui_layout_tests PRIVATE /W4 /permissive- /utf-8 /Zc:__cplusplus)
        target_link_options(ui_layout_tests PRIVATE /MANIFEST:NO)
    else()
        target_compile_options(ui_layout_tests PRIVATE -Wall -Wextra)
    endif()
    add_test(NAME ui_layout COMMAND ui_layout_tests)
    set_tests_properties(ui_layout PROPERTIES TIMEOUT 60 RESOURCE_LOCK firewallx_ui)

    add_executable(traffic_attribution_options_tests
        tests/traffic_attribution_options_tests.cpp
        TrafficAttributionOptions.cpp
        Settings.cpp
        Util.cpp
        TlsReassembly.cpp
        StringRes.cpp
    )
    target_include_directories(traffic_attribution_options_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_definitions(traffic_attribution_options_tests PRIVATE
        UNICODE _UNICODE
        WIN32_LEAN_AND_MEAN NOMINMAX
        _WIN32_WINNT=0x0A00 WINVER=0x0A00 NTDDI_VERSION=0x0A000010
    )
    target_link_libraries(traffic_attribution_options_tests PRIVATE
        winsqlite3
        iphlpapi ws2_32 comctl32 uxtheme gdi32 user32
        shell32 shlwapi ole32 advapi32 comdlg32
    )
    if(MSVC)
        target_compile_options(traffic_attribution_options_tests PRIVATE
            /W4 /permissive- /utf-8 /Zc:__cplusplus
        )
    else()
        target_compile_options(traffic_attribution_options_tests PRIVATE -Wall -Wextra)
    endif()
    add_test(NAME traffic_attribution_options COMMAND traffic_attribution_options_tests)

    add_executable(process_protection_options_tests
        tests/process_protection_options_tests.cpp
        ProcessProtectionOptions.cpp
        Settings.cpp
        Util.cpp
        TlsReassembly.cpp
        StringRes.cpp
    )
    target_include_directories(process_protection_options_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_definitions(process_protection_options_tests PRIVATE
        UNICODE _UNICODE
        WIN32_LEAN_AND_MEAN NOMINMAX
        _WIN32_WINNT=0x0A00 WINVER=0x0A00 NTDDI_VERSION=0x0A000010
    )
    target_link_libraries(process_protection_options_tests PRIVATE
        winsqlite3
        iphlpapi ws2_32 comctl32 uxtheme gdi32 user32
        shell32 shlwapi ole32 advapi32 comdlg32
    )
    if(MSVC)
        target_compile_options(process_protection_options_tests PRIVATE
            /W4 /permissive- /utf-8 /Zc:__cplusplus
        )
    else()
        target_compile_options(process_protection_options_tests PRIVATE -Wall -Wextra)
    endif()
    add_test(NAME process_protection_options COMMAND process_protection_options_tests)
    add_test(NAME process_protection_runtime COMMAND process_protection_options_tests --real-policy)
    set_tests_properties(process_protection_options process_protection_runtime PROPERTIES TIMEOUT 60)

    # Настоящие Ingest/AskWindow, но без подключения к драйверу и изменения SCM.
    add_executable(ask_actions_tests
        tests/ask_actions_tests.cpp
        tests/rule_editor_ui_tests.cpp
        tests/app_interface_ingest_tests.h
        tests/interface_binding_editor_tests.h
        AskWindow.cpp
        ProcessIcon.cpp
        AskQueue.cpp
        RuleEditor.cpp
        AppRulesEditor.cpp
        RuleDialogs.cpp
        RulePresets.cpp
        Settings.cpp
        TrafficAttributionOptions.cpp
        ProcessProtectionOptions.cpp
        Ingest.cpp
        NdisTransport.cpp
        FlowStore.cpp
        OwnerLookup.cpp
        FirewallPolicy.cpp
        FirewallPolicySetting.cpp
        Rules.cpp
        RuleDb.cpp
        MacroAddr.cpp
        StringRes.cpp
        Util.cpp
        UiKit.cpp
        TlsReassembly.cpp
        quic_sni.cpp
        ThreadSuspend.cpp
        ServiceThreadId.cpp
        ServiceControl.cpp
        duplex_pipe/duplex_pipe_client.cpp
        duplex_pipe/duplex_pipe_server.cpp
        duplex_pipe/pipe_transport.cpp
        pipe_support.cpp
        rules_matching_tests.rc
    )
    target_include_directories(ask_actions_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_definitions(ask_actions_tests PRIVATE
        UNICODE _UNICODE
        WIN32_LEAN_AND_MEAN NOMINMAX
        _WIN32_WINNT=0x0A00 WINVER=0x0A00 NTDDI_VERSION=0x0A000010
        FIREWALLX_TEST_VERDICTS
    )
    target_link_libraries(ask_actions_tests PRIVATE
        firewallx_ndis_binding firewallx_nsi_import fwpuclnt
        winsqlite3 bcrypt
        iphlpapi ws2_32 comctl32 uxtheme gdi32 user32
        shell32 shlwapi ole32 advapi32 comdlg32 ntdll
        xmllite windowscodecs
    )
    if(MSVC)
        target_compile_options(ask_actions_tests PRIVATE
            /W4 /permissive- /utf-8 /Zc:__cplusplus
        )
        target_link_options(ask_actions_tests PRIVATE /MANIFEST:NO)
    else()
        target_compile_options(ask_actions_tests PRIVATE -Wall -Wextra)
    endif()
    # Медленные проверки окон запускаются отдельно, не конкурируя за фокус.
    add_test(NAME ask_actions COMMAND ask_actions_tests --ctest-main)
    add_test(NAME ndis_service_policy COMMAND ask_actions_tests --ndis-service-policy-only)
    set_tests_properties(ndis_service_policy PROPERTIES TIMEOUT 30 LABELS "no-driver")
    add_test(NAME ask_actions_layout COMMAND ask_actions_tests --rule-layout-only)
    add_test(NAME ask_actions_inheritance_editor COMMAND ask_actions_tests --inheritance-editor-only)
    add_test(NAME ask_actions_pid_editor COMMAND ask_actions_tests --rule-pid-only)
    set_tests_properties(ask_actions ask_actions_inheritance_editor ask_actions_pid_editor
        PROPERTIES TIMEOUT 90 RESOURCE_LOCK firewallx_ui)
    set_tests_properties(ask_actions_layout PROPERTIES TIMEOUT 120 RESOURCE_LOCK firewallx_ui)

    add_executable(windows_firewall_options_tests
        tests/windows_firewall_options_tests.cpp
        WindowsFirewallOptions.cpp
    )
    target_include_directories(windows_firewall_options_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_definitions(windows_firewall_options_tests PRIVATE
        UNICODE _UNICODE
        WIN32_LEAN_AND_MEAN NOMINMAX
        _WIN32_WINNT=0x0A00 WINVER=0x0A00 NTDDI_VERSION=0x0A000010
    )
    target_link_libraries(windows_firewall_options_tests PRIVATE ole32 uuid)
    if(MSVC)
        target_compile_options(windows_firewall_options_tests PRIVATE
            /W4 /permissive- /utf-8 /Zc:__cplusplus
        )
    else()
        target_compile_options(windows_firewall_options_tests PRIVATE -Wall -Wextra)
    endif()
    add_test(NAME windows_firewall_options COMMAND windows_firewall_options_tests)

    add_executable(wfp_audit_tests
        tests/wfp_audit_tests.cpp
        WfpAudit.cpp
    )
    target_include_directories(wfp_audit_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_definitions(wfp_audit_tests PRIVATE
        UNICODE _UNICODE
        WIN32_LEAN_AND_MEAN NOMINMAX
        _WIN32_WINNT=0x0A00 WINVER=0x0A00 NTDDI_VERSION=0x0A000010
    )
    target_link_libraries(wfp_audit_tests PRIVATE advapi32)
    if(MSVC)
        target_compile_options(wfp_audit_tests PRIVATE
            /W4 /permissive- /utf-8 /Zc:__cplusplus
        )
    else()
        target_compile_options(wfp_audit_tests PRIVATE -Wall -Wextra)
    endif()
    add_test(NAME wfp_audit COMMAND wfp_audit_tests)

    add_executable(startup_options_tests
        tests/startup_options_tests.cpp
        StartupOptions.cpp
        Util.cpp
        TlsReassembly.cpp
        StringRes.cpp
    )
    target_include_directories(startup_options_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_definitions(startup_options_tests PRIVATE
        UNICODE _UNICODE
        WIN32_LEAN_AND_MEAN NOMINMAX
        _WIN32_WINNT=0x0A00 WINVER=0x0A00 NTDDI_VERSION=0x0A000010
    )
    target_link_libraries(startup_options_tests PRIVATE
        taskschd oleaut32
        iphlpapi ws2_32 comctl32 uxtheme gdi32 user32
        shell32 shlwapi ole32 advapi32 comdlg32
    )
    if(MSVC)
        target_compile_options(startup_options_tests PRIVATE
            /W4 /permissive- /utf-8 /Zc:__cplusplus
        )
    else()
        target_compile_options(startup_options_tests PRIVATE -Wall -Wextra)
    endif()
    add_test(NAME startup_options COMMAND startup_options_tests)

    add_executable(flowstore_lifecycle_tests
        tests/flowstore_lifecycle_tests.cpp
        FlowStore.cpp
        MacroAddr.cpp
        Settings.cpp
        Util.cpp
        StringRes.cpp
    )
    target_include_directories(flowstore_lifecycle_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/src
    )
    target_compile_definitions(flowstore_lifecycle_tests PRIVATE
        UNICODE _UNICODE
        WIN32_LEAN_AND_MEAN NOMINMAX
        _WIN32_WINNT=0x0A00 WINVER=0x0A00 NTDDI_VERSION=0x0A000010
    )
    target_link_libraries(flowstore_lifecycle_tests PRIVATE
        winsqlite3 iphlpapi ws2_32 comctl32 uxtheme gdi32 user32
        shell32 shlwapi ole32 advapi32 comdlg32
    )
    if(MSVC)
        target_compile_options(flowstore_lifecycle_tests PRIVATE
            /W4 /permissive- /utf-8 /Zc:__cplusplus
        )
        # Debug сохраняет UI-функции Util.cpp: импорт ordinal 381 требует
        # Common Controls v6 уже при загрузке exe, до входа в main.
        target_link_options(flowstore_lifecycle_tests PRIVATE
            "/MANIFESTDEPENDENCY:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'"
        )
    else()
        target_compile_options(flowstore_lifecycle_tests PRIVATE -Wall -Wextra)
    endif()
    add_test(NAME flowstore_lifecycle COMMAND flowstore_lifecycle_tests)

    add_executable(verdict_session_tests
        tests/verdict_session_tests.cpp
        VerdictSession.h
    )
    target_include_directories(verdict_session_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
    )
    if(MSVC)
        target_compile_options(verdict_session_tests PRIVATE
            /W4 /permissive- /utf-8 /Zc:__cplusplus
        )
    else()
        target_compile_options(verdict_session_tests PRIVATE -Wall -Wextra)
    endif()
    add_test(NAME verdict_session COMMAND verdict_session_tests)

    add_executable(kext_app_interface_tests tests/kext_app_interface_tests.cpp)
    target_include_directories(kext_app_interface_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_definitions(kext_app_interface_tests PRIVATE
        UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX
        _WIN32_WINNT=0x0A00 WINVER=0x0A00 NTDDI_VERSION=0x0A000010
    )
    target_link_libraries(kext_app_interface_tests PRIVATE advapi32 fwpuclnt firewallx_nsi_import)
    if(MSVC)
        target_compile_options(kext_app_interface_tests PRIVATE /W4 /WX /permissive- /utf-8 /Zc:__cplusplus)
    else()
        target_compile_options(kext_app_interface_tests PRIVATE -Wall -Wextra)
    endif()
    add_test(NAME kext_app_interface COMMAND kext_app_interface_tests)
    set_tests_properties(kext_app_interface PROPERTIES TIMEOUT 30 LABELS "no-driver")

    add_executable(kext_connection_tests tests/kext_connection_tests.cpp)
    target_include_directories(kext_connection_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_definitions(kext_connection_tests PRIVATE
        UNICODE _UNICODE
        WIN32_LEAN_AND_MEAN NOMINMAX
        _WIN32_WINNT=0x0A00 WINVER=0x0A00 NTDDI_VERSION=0x0A000010
    )
    target_link_libraries(kext_connection_tests PRIVATE advapi32)
    if(MSVC)
        target_compile_options(kext_connection_tests PRIVATE /W4 /permissive- /utf-8 /Zc:__cplusplus)
    else()
        target_compile_options(kext_connection_tests PRIVATE -Wall -Wextra)
    endif()
    add_test(NAME kext_connection COMMAND kext_connection_tests)
    set_tests_properties(kext_connection PROPERTIES TIMEOUT 10)

    add_executable(process_event_tests tests/process_event_tests.cpp ProcessEvents.h)
    target_include_directories(process_event_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_definitions(process_event_tests PRIVATE
        UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX
        _WIN32_WINNT=0x0A00 WINVER=0x0A00 NTDDI_VERSION=0x0A000010
    )
    target_link_libraries(process_event_tests PRIVATE advapi32)
    if(MSVC)
        target_compile_options(process_event_tests PRIVATE /W4 /WX /permissive- /utf-8 /Zc:__cplusplus)
    endif()
    add_test(NAME process_events COMMAND process_event_tests)
    set_tests_properties(process_events PROPERTIES TIMEOUT 30 LABELS "no-driver")

    # Ограниченный ручной прогон сам загружает драйвер и не включён в CTest.
    add_executable(kext_process_runtime tests/process_events_runtime.cpp)
    target_include_directories(kext_process_runtime PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_definitions(kext_process_runtime PRIVATE
        UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX
        _WIN32_WINNT=0x0A00 WINVER=0x0A00 NTDDI_VERSION=0x0A000010
    )
    target_link_libraries(kext_process_runtime PRIVATE advapi32)
    if(MSVC)
        target_compile_options(kext_process_runtime PRIVATE /W4 /WX /permissive- /utf-8 /Zc:__cplusplus)
        target_link_options(kext_process_runtime PRIVATE /ENTRY:wmainCRTStartup)
    else()
        target_link_options(kext_process_runtime PRIVATE -municode)
    endif()

    # Полный путь чтения и raw-pipe без службы и настоящего драйвера.
    add_executable(large_record_tests
        tests/large_record_tests.cpp
        duplex_pipe/pipe_transport.cpp
        ReadBuffer.h
    )
    target_include_directories(large_record_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_definitions(large_record_tests PRIVATE
        UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX
        _WIN32_WINNT=0x0A00 WINVER=0x0A00 NTDDI_VERSION=0x0A000010
    )
    target_link_libraries(large_record_tests PRIVATE advapi32)
    if(MSVC)
        target_compile_options(large_record_tests PRIVATE /W4 /WX /permissive- /utf-8 /Zc:__cplusplus)
    endif()
    add_test(NAME large_records COMMAND large_record_tests)
    set_tests_properties(large_records PROPERTIES TIMEOUT 180 LABELS "no-driver")

    # Барьер ожидает callbacks и опустошение pipe без настоящей службы.
    add_executable(pipe_drain_tests
        tests/pipe_drain_tests.cpp
        duplex_pipe/duplex_pipe_client.cpp
        duplex_pipe/pipe_transport.cpp
        pipe_support.cpp
    )
    target_include_directories(pipe_drain_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_definitions(pipe_drain_tests PRIVATE
        FIREWALLX_PIPE_TESTS UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX
        _WIN32_WINNT=0x0A00 WINVER=0x0A00 NTDDI_VERSION=0x0A000010
    )
    if(MSVC)
        target_compile_options(pipe_drain_tests PRIVATE /W4 /WX /permissive- /utf-8 /Zc:__cplusplus)
    endif()
    add_test(NAME pipe_drain COMMAND pipe_drain_tests)
    set_tests_properties(pipe_drain PROPERTIES TIMEOUT 60 LABELS "no-driver")

    # Запускается вручную: замеры CPU не должны конкурировать с тестами CTest.
    add_executable(pipe_transport_bench tests/pipe_transport_bench.cpp duplex_pipe/pipe_transport.cpp)
    target_include_directories(pipe_transport_bench PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_definitions(pipe_transport_bench PRIVATE
        UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00 WINVER=0x0A00
    )
    target_link_libraries(pipe_transport_bench PRIVATE psapi)
    if(MSVC)
        target_compile_options(pipe_transport_bench PRIVATE /W4 /WX /permissive- /utf-8 /Zc:__cplusplus)
    endif()

    # Имена устройства и DriverReady проверяются без обращения к настоящему драйверу.
    add_executable(ndis_binding_tests tests/ndis_binding_tests.cpp)
    target_link_libraries(ndis_binding_tests PRIVATE firewallx_ndis_binding)
    if(MSVC)
        target_compile_options(ndis_binding_tests PRIVATE /W4 /WX /permissive- /utf-8 /Zc:__cplusplus)
    endif()
    add_test(NAME ndis_binding COMMAND ndis_binding_tests)
    set_tests_properties(ndis_binding PROPERTIES TIMEOUT 10 LABELS "no-driver")

    add_executable(ndis_binding_service_tests tests/ndis_binding_service_tests.cpp)
    target_include_directories(ndis_binding_service_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_definitions(ndis_binding_service_tests PRIVATE
        UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX
        _WIN32_WINNT=0x0A00 WINVER=0x0A00 NTDDI_VERSION=0x0A000010
    )
    target_link_libraries(ndis_binding_service_tests PRIVATE advapi32)
    if(MSVC)
        target_compile_options(ndis_binding_service_tests PRIVATE /W4 /WX /permissive- /utf-8 /Zc:__cplusplus)
    endif()
    add_test(NAME ndis_binding_service COMMAND ndis_binding_service_tests)
    set_tests_properties(ndis_binding_service PROPERTIES TIMEOUT 10 LABELS "no-driver")

    add_executable(ndis_binding_process_tests tests/ndis_binding_process_tests.cpp)
    target_link_libraries(ndis_binding_process_tests PRIVATE firewallx_ndis_binding)
    set_target_properties(ndis_binding_process_tests PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/binding process tests")
    if(MSVC)
        target_compile_options(ndis_binding_process_tests PRIVATE /W4 /WX /permissive- /utf-8 /Zc:__cplusplus)
    endif()
    add_test(NAME ndis_binding_process COMMAND ndis_binding_process_tests)
    set_tests_properties(ndis_binding_process PROPERTIES TIMEOUT 20 LABELS "no-driver")

    add_executable(ndis_client_identity_tests tests/ndis_client_identity_tests.cpp)
    target_include_directories(ndis_client_identity_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_definitions(ndis_client_identity_tests PRIVATE
        UNICODE _UNICODE
        WIN32_LEAN_AND_MEAN NOMINMAX
        _WIN32_WINNT=0x0A00 WINVER=0x0A00 NTDDI_VERSION=0x0A000010
    )
    target_link_libraries(ndis_client_identity_tests PRIVATE advapi32)
    if(MSVC)
        target_compile_options(ndis_client_identity_tests PRIVATE /W4 /permissive- /utf-8 /Zc:__cplusplus)
    else()
        target_compile_options(ndis_client_identity_tests PRIVATE -Wall -Wextra)
    endif()
    add_test(NAME ndis_client_identity COMMAND ndis_client_identity_tests)
    set_tests_properties(ndis_client_identity PROPERTIES TIMEOUT 10)

    # Wire-кодек проверяется без открытия устройства и именованных событий драйвера.
    add_executable(ndis_bandwidth_tests tests/ndis_bandwidth_tests.cpp)
    target_include_directories(ndis_bandwidth_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_definitions(ndis_bandwidth_tests PRIVATE
        UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX
        _WIN32_WINNT=0x0A00 WINVER=0x0A00 NTDDI_VERSION=0x0A000010
    )
    target_link_libraries(ndis_bandwidth_tests PRIVATE advapi32)
    if(MSVC)
        target_compile_options(ndis_bandwidth_tests PRIVATE /W4 /WX /permissive- /utf-8 /Zc:__cplusplus)
    else()
        target_compile_options(ndis_bandwidth_tests PRIVATE -Wall -Wextra)
    endif()
    add_test(NAME ndis_bandwidth COMMAND ndis_bandwidth_tests)
    set_tests_properties(ndis_bandwidth PROPERTIES TIMEOUT 10 LABELS "no-driver")

    add_executable(api_compatibility_tests
        tests/api_compatibility_tests.cpp
        duplex_pipe/pipe_transport.cpp
    )
    target_include_directories(api_compatibility_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_definitions(api_compatibility_tests PRIVATE
        UNICODE _UNICODE
        WIN32_LEAN_AND_MEAN NOMINMAX
        _WIN32_WINNT=0x0A00 WINVER=0x0A00 NTDDI_VERSION=0x0A000010
    )
    target_link_libraries(api_compatibility_tests PRIVATE advapi32)
    if(MSVC)
        target_compile_options(api_compatibility_tests PRIVATE /W4 /permissive- /utf-8 /Zc:__cplusplus)
    else()
        target_compile_options(api_compatibility_tests PRIVATE -Wall -Wextra)
    endif()
    add_test(NAME driver_api_version COMMAND api_compatibility_tests --driver)
    add_test(NAME pipe_api_compatibility COMMAND api_compatibility_tests --pipe)
    set_tests_properties(driver_api_version pipe_api_compatibility PROPERTIES TIMEOUT 15)

    add_executable(thread_suspend_tests
        tests/thread_suspend_tests.cpp
    )
    target_include_directories(thread_suspend_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
    )
    target_compile_definitions(thread_suspend_tests PRIVATE
        UNICODE _UNICODE
        WIN32_LEAN_AND_MEAN NOMINMAX
        _WIN32_WINNT=0x0A00 WINVER=0x0A00 NTDDI_VERSION=0x0A000010
    )
    if(MSVC)
        target_compile_options(thread_suspend_tests PRIVATE
            /W4 /permissive- /utf-8 /Zc:__cplusplus
        )
    else()
        target_compile_options(thread_suspend_tests PRIVATE -Wall -Wextra -municode)
        target_link_options(thread_suspend_tests PRIVATE -municode)
    endif()
    add_test(NAME thread_suspend COMMAND thread_suspend_tests)
    set_tests_properties(thread_suspend PROPERTIES TIMEOUT 30)

    add_executable(service_thread_id_tests
        tests/service_thread_id_tests.cpp
        ServiceThreadId.cpp
    )
    target_include_directories(service_thread_id_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
    )
    target_compile_definitions(service_thread_id_tests PRIVATE
        UNICODE _UNICODE
        WIN32_LEAN_AND_MEAN NOMINMAX
        _WIN32_WINNT=0x0A00 WINVER=0x0A00 NTDDI_VERSION=0x0A000010
    )
    target_link_libraries(service_thread_id_tests PRIVATE advapi32)
    if(MSVC)
        target_compile_options(service_thread_id_tests PRIVATE
            /W4 /permissive- /utf-8 /Zc:__cplusplus
        )
    else()
        target_compile_options(service_thread_id_tests PRIVATE -Wall -Wextra -municode)
        target_link_options(service_thread_id_tests PRIVATE -municode)
    endif()
    add_test(NAME service_thread_id COMMAND service_thread_id_tests)
    set_tests_properties(service_thread_id PROPERTIES TIMEOUT 30)

    add_executable(tls_reassembly_tests
        tests/tls_reassembly_tests.cpp
        TlsReassembly.cpp
        Util.cpp
        StringRes.cpp
    )
    target_include_directories(tls_reassembly_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/src
    )
    target_compile_definitions(tls_reassembly_tests PRIVATE
        UNICODE _UNICODE
        WIN32_LEAN_AND_MEAN NOMINMAX
        _WIN32_WINNT=0x0A00 WINVER=0x0A00 NTDDI_VERSION=0x0A000010
    )
    target_link_libraries(tls_reassembly_tests PRIVATE
        iphlpapi ws2_32 comctl32 uxtheme gdi32 user32
        shell32 shlwapi ole32 advapi32 comdlg32
    )
    if(MSVC)
        target_compile_options(tls_reassembly_tests PRIVATE
            /W4 /permissive- /utf-8 /Zc:__cplusplus
        )
    else()
        target_compile_options(tls_reassembly_tests PRIVATE -Wall -Wextra)
    endif()
    add_test(NAME tls_reassembly COMMAND tls_reassembly_tests)

    add_executable(http_host_tests
        tests/http_host_tests.cpp
        Util.cpp
        TlsReassembly.cpp
        StringRes.cpp
    )
    target_include_directories(http_host_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/src
    )
    target_compile_definitions(http_host_tests PRIVATE
        UNICODE _UNICODE
        WIN32_LEAN_AND_MEAN NOMINMAX
        _WIN32_WINNT=0x0A00 WINVER=0x0A00 NTDDI_VERSION=0x0A000010
    )
    target_link_libraries(http_host_tests PRIVATE
        iphlpapi ws2_32 comctl32 uxtheme gdi32 user32
        shell32 shlwapi ole32 advapi32 comdlg32
    )
    if(MSVC)
        target_compile_options(http_host_tests PRIVATE
            /W4 /permissive- /utf-8 /Zc:__cplusplus
        )
    else()
        target_compile_options(http_host_tests PRIVATE -Wall -Wextra)
    endif()
    add_test(NAME http_host COMMAND http_host_tests)

    add_executable(dns_query_tests
        tests/dns_query_tests.cpp
        Util.cpp
        TlsReassembly.cpp
        StringRes.cpp
    )
    target_include_directories(dns_query_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_definitions(dns_query_tests PRIVATE
        UNICODE _UNICODE
        WIN32_LEAN_AND_MEAN NOMINMAX
        _WIN32_WINNT=0x0A00 WINVER=0x0A00 NTDDI_VERSION=0x0A000010
    )
    target_link_libraries(dns_query_tests PRIVATE
        iphlpapi ws2_32 comctl32 uxtheme gdi32 user32
        shell32 shlwapi ole32 advapi32 comdlg32
    )
    if(MSVC)
        target_compile_options(dns_query_tests PRIVATE
            /W4 /permissive- /utf-8 /Zc:__cplusplus
        )
        # Debug сохраняет LoadIconWithScaleDown из Util.cpp: нужен Common Controls v6.
        target_link_options(dns_query_tests PRIVATE
            "/MANIFESTDEPENDENCY:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'"
        )
    else()
        target_compile_options(dns_query_tests PRIVATE -Wall -Wextra)
    endif()
    add_test(NAME dns_query COMMAND dns_query_tests)

    add_executable(win_error_tests
        tests/win_error_tests.cpp
        Util.cpp
        TlsReassembly.cpp
        StringRes.cpp
        rules_matching_tests.rc
    )
    foreach(property INCLUDE_DIRECTORIES COMPILE_DEFINITIONS COMPILE_OPTIONS LINK_OPTIONS LINK_LIBRARIES)
        get_target_property(value dns_query_tests ${property})
        if(value)
            set_property(TARGET win_error_tests PROPERTY ${property} "${value}")
        endif()
    endforeach()
    if(MSVC)
        target_link_options(win_error_tests PRIVATE /MANIFEST:NO)
    endif()
    add_test(NAME win_error COMMAND win_error_tests)
    set_tests_properties(win_error PROPERTIES TIMEOUT 30)

    add_executable(rules_matching_tests
        tests/rules_matching_tests.cpp
        RuleDialogs.cpp
        UiKit.cpp
        ProcessIcon.cpp
        Settings.cpp
        Rules.cpp
        RuleDb.cpp
        MacroAddr.cpp
        ServiceInfo.cpp
        StringRes.cpp
        Util.cpp
        rules_matching_tests.rc
    )
    set_property(SOURCE rules_matching_tests.rc APPEND PROPERTY OBJECT_DEPENDS
        ${CMAKE_CURRENT_SOURCE_DIR}/rules_matching_tests.manifest
        ${CMAKE_CURRENT_SOURCE_DIR}/resource.h
        ${CMAKE_CURRENT_SOURCE_DIR}/RulePresetsResource.h
        ${CMAKE_CURRENT_SOURCE_DIR}/RulePresets.rc
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_ru.rc
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_en.rc
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_kr.rc
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_zh.rc
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_uk.rc
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_de.rc
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_fr.rc
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_es.rc
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_ar.rc
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_hi.rc
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_lv.rc
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_lt.rc
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_et.rc
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_ro.rc
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_sv.rc
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_pl.rc
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_vi.rc
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_pt.rc
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_it.rc
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_fa.rc
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_ja.rc
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_tr.rc
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_id.rc
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_cs.rc
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_th.rc
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_pt_br.rc
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_zh_tw.rc
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_hu.rc
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_el.rc
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_nl.rc
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_bg.rc
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_da.rc
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_nb.rc
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/firewall_fi.rc
    )
    target_include_directories(rules_matching_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/src
    )
    target_compile_definitions(rules_matching_tests PRIVATE
        UNICODE _UNICODE
        WIN32_LEAN_AND_MEAN NOMINMAX
        _WIN32_WINNT=0x0A00 WINVER=0x0A00 NTDDI_VERSION=0x0A000010
    )
    target_link_libraries(rules_matching_tests PRIVATE
        winsqlite3
        iphlpapi ws2_32 comctl32 uxtheme gdi32 user32
        shell32 shlwapi ole32 advapi32 comdlg32
        xmllite windowscodecs
    )
    if(MSVC)
        target_compile_options(rules_matching_tests PRIVATE
            /W4 /permissive- /utf-8 /Zc:__cplusplus
        )
        target_link_options(rules_matching_tests PRIVATE /MANIFEST:NO)
    else()
        target_compile_options(rules_matching_tests PRIVATE -Wall -Wextra)
    endif()
    add_test(NAME rules_matching COMMAND rules_matching_tests)

    # Отдельный синтетический бенчмарк: не входит в CTest и не запускает драйвер.
    # ServiceInfo.cpp подключён в тесте с подменой только вызовов SCM.
    add_executable(rules_lookup_bench EXCLUDE_FROM_ALL
        tests/rules_lookup_bench.cpp
        Settings.cpp
        Rules.cpp
        RuleDb.cpp
        MacroAddr.cpp
        StringRes.cpp
        Util.cpp
        rules_matching_tests.rc
    )
    target_include_directories(rules_lookup_bench PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_definitions(rules_lookup_bench PRIVATE
        UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX
        _WIN32_WINNT=0x0A00 WINVER=0x0A00 NTDDI_VERSION=0x0A000010
    )
    target_link_libraries(rules_lookup_bench PRIVATE
        winsqlite3 iphlpapi ws2_32 user32 shell32 shlwapi ole32 advapi32 comctl32
    )
    if(MSVC)
        target_compile_options(rules_lookup_bench PRIVATE /W4 /permissive- /utf-8 /Zc:__cplusplus)
        target_link_options(rules_lookup_bench PRIVATE /MANIFEST:NO)
    endif()

    set(monitor_test_sources
        Monitor.cpp
        FlowStore.cpp
        OwnerLookup.cpp
        FirewallPolicy.cpp
        FirewallPolicySetting.cpp
        Settings.cpp
        Rules.cpp
        RuleDb.cpp
        MacroAddr.cpp
        ServiceInfo.cpp
        StringRes.cpp
        Util.cpp
        rules_matching_tests.rc
    )
    add_executable(firewall_policy_tests tests/firewall_policy_tests.cpp ${monitor_test_sources})
    # Тест включает Monitor.cpp с управляемым чтением таблиц TCP/UDP.
    set(storage_retention_sources ${monitor_test_sources})
    list(REMOVE_ITEM storage_retention_sources Monitor.cpp)
    add_executable(storage_retention_tests tests/storage_retention_tests.cpp ${storage_retention_sources})
    foreach(target firewall_policy_tests storage_retention_tests)
        target_include_directories(${target} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}
        )
        target_compile_definitions(${target} PRIVATE
            UNICODE _UNICODE
            WIN32_LEAN_AND_MEAN NOMINMAX
            _WIN32_WINNT=0x0A00 WINVER=0x0A00 NTDDI_VERSION=0x0A000010
        )
        target_link_libraries(${target} PRIVATE
            winsqlite3
            iphlpapi ws2_32 comctl32 uxtheme gdi32 user32
            shell32 shlwapi ole32 advapi32 comdlg32
        )
        if(MSVC)
            target_compile_options(${target} PRIVATE
                /W4 /permissive- /utf-8 /Zc:__cplusplus
            )
            target_link_options(${target} PRIVATE /MANIFEST:NO)
        else()
            target_compile_options(${target} PRIVATE -Wall -Wextra)
        endif()
    endforeach()
    add_test(NAME firewall_policy COMMAND firewall_policy_tests)
    add_test(NAME storage_retention COMMAND storage_retention_tests)
    set_tests_properties(storage_retention PROPERTIES TIMEOUT 60)

    # Снимок SCM заменён управляемой заглушкой, дескрипторы процессов настоящие.
    add_executable(process_handle_tests
        tests/process_handle_tests.cpp
        Settings.cpp
        FirewallPolicy.cpp
        Rules.cpp
        RuleDb.cpp
        MacroAddr.cpp
        StringRes.cpp
        Util.cpp
        rules_matching_tests.rc
    )
    target_include_directories(process_handle_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
    )
    target_compile_definitions(process_handle_tests PRIVATE
        UNICODE _UNICODE
        WIN32_LEAN_AND_MEAN NOMINMAX
        _WIN32_WINNT=0x0A00 WINVER=0x0A00 NTDDI_VERSION=0x0A000010
    )
    target_link_libraries(process_handle_tests PRIVATE
        winsqlite3
        iphlpapi ws2_32 comctl32 uxtheme gdi32 user32
        shell32 shlwapi ole32 advapi32 comdlg32
    )
    if(MSVC)
        target_compile_options(process_handle_tests PRIVATE
            /W4 /permissive- /utf-8 /Zc:__cplusplus
        )
        target_link_options(process_handle_tests PRIVATE /MANIFEST:NO)
    else()
        target_compile_options(process_handle_tests PRIVATE -Wall -Wextra)
    endif()
    add_test(NAME process_handle COMMAND process_handle_tests)

    foreach(target ask_actions_tests flowstore_lifecycle_tests rules_matching_tests
                   rules_lookup_bench firewall_policy_tests storage_retention_tests process_handle_tests)
        target_link_libraries(${target} PRIVATE firewallx_network_interfaces)
    endforeach()

    # Управляемые уведомления и адаптеры; системные сетевые настройки не меняются.
    # Watcher и MacroAddr включены в тест с подменой только Windows API и часов.
    add_executable(network_interface_watcher_tests
        tests/network_interface_watcher_tests.cpp tests/interface_filter_tests.h
        tests/app_interface_preference_tests.h FirewallPolicy.cpp
        Rules.cpp RuleDb.cpp ServiceInfo.cpp Settings.cpp
        Util.cpp StringRes.cpp rules_matching_tests.rc
    )
    foreach(property INCLUDE_DIRECTORIES COMPILE_DEFINITIONS COMPILE_OPTIONS LINK_OPTIONS LINK_LIBRARIES)
        get_target_property(value flowstore_lifecycle_tests ${property})
        if(value)
            if(property STREQUAL "LINK_LIBRARIES")
                list(REMOVE_ITEM value firewallx_network_interfaces)
            endif()
            set_property(TARGET network_interface_watcher_tests PROPERTY ${property} "${value}")
        endif()
    endforeach()
    target_link_libraries(network_interface_watcher_tests PRIVATE winsqlite3)
    add_test(NAME network_interface_watcher COMMAND network_interface_watcher_tests)
    set_tests_properties(network_interface_watcher PROPERTIES TIMEOUT 30)

    add_executable(network_interface_watcher_live_tests
        tests/network_interface_watcher_live_tests.cpp Settings.cpp Util.cpp StringRes.cpp rules_matching_tests.rc)
    target_link_libraries(network_interface_watcher_live_tests PRIVATE
        firewallx_network_interfaces winsqlite3 ws2_32 comctl32 uxtheme gdi32 user32 shell32 shlwapi ole32)
    if(MSVC)
        target_compile_options(network_interface_watcher_live_tests PRIVATE /W4 /WX /permissive- /utf-8 /Zc:__cplusplus)
    endif()
    add_test(NAME network_interface_watcher_live COMMAND network_interface_watcher_live_tests)
    set_tests_properties(network_interface_watcher_live PROPERTIES TIMEOUT 30)

    # Debug оставляет в Util.cpp импорт LoadIconWithScaleDown. Без манифеста
    # загружается comctl32 v5, и эти тесты завершаются до входа в main.
    if(MSVC)
        foreach(target traffic_attribution_options_tests process_protection_options_tests
                       startup_options_tests http_host_tests)
            target_link_options(${target} PRIVATE
                "/MANIFESTDEPENDENCY:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'")
        endforeach()
    endif()
endif()
