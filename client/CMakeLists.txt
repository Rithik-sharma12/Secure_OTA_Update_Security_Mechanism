cmake_minimum_required(VERSION 3.16)
project(SecureOTAClient C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ── Compiler hardening flags ────────────────────────────────────────────────
add_compile_options(
    -Wall
    -Wextra
    -Wpedantic
    -Werror=format-security
    -Wno-unused-parameter
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()

# ── Source files ─────────────────────────────────────────────────────────────
set(OTA_SOURCES
    ota_client.c
    rollback.c
    delta_update.c
)

# Platform selection: default to a POSIX stub for host testing
option(OTA_PLATFORM_ESP32  "Build for ESP32 (requires ESP-IDF)"  OFF)
option(OTA_PLATFORM_POSIX  "Build POSIX stub (host testing)"      ON)

if(OTA_PLATFORM_ESP32)
    list(APPEND OTA_SOURCES hal_esp32.c)
    # ESP-IDF provides its own toolchain; these variables should be set
    # by the ESP-IDF CMake integration.
    add_definitions(-DOTA_PLATFORM_ESP32)
elseif(OTA_PLATFORM_POSIX)
    list(APPEND OTA_SOURCES hal_posix_stub.c)
    add_definitions(-DOTA_PLATFORM_POSIX)
endif()

# ── Library target ───────────────────────────────────────────────────────────
add_library(ota_client STATIC ${OTA_SOURCES})

target_include_directories(ota_client PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# ── mbedTLS dependency ───────────────────────────────────────────────────────
# When building for the host (testing), link against the system mbedTLS.
if(OTA_PLATFORM_POSIX)
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(MBEDTLS QUIET mbedtls)
    endif()

    if(MBEDTLS_FOUND)
        target_include_directories(ota_client PRIVATE ${MBEDTLS_INCLUDE_DIRS})
        target_link_libraries(ota_client PRIVATE ${MBEDTLS_LIBRARIES})
    else()
        # Fallback: expect mbedTLS installed under /usr/local
        target_link_libraries(ota_client PRIVATE mbedcrypto mbedtls mbedx509)
    endif()
endif()

# ── Unit test executable (host only) ─────────────────────────────────────────
if(OTA_PLATFORM_POSIX AND BUILD_TESTING)
    enable_testing()
    add_executable(test_ota_client
        tests/test_ota_client.c
    )
    target_link_libraries(test_ota_client PRIVATE ota_client)
    add_test(NAME OTAClientTests COMMAND test_ota_client)
endif()

# ── Install ───────────────────────────────────────────────────────────────────
install(TARGETS ota_client
    ARCHIVE DESTINATION lib
)
install(FILES
    ota_client.h
    hal.h
    rollback.h
    delta_update.h
    DESTINATION include/ota
)
