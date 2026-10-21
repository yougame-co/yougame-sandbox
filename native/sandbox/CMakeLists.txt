# yougame-sandbox: runs a game or emulator inside a Windows AppContainer + job object
# (launcher.cpp, see docs/DESKTOP_SANDBOX.md). sandbox-probe is the containment test's stand-in
# for a compromised game; it is built for the tests and never installed or shipped.
# Built by desktop/scripts/build-libretro.mjs next to yougame-libretro. Windows only.
cmake_minimum_required(VERSION 3.24)
project(yougame_sandbox VERSION 1.0 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# The static CRT: the launcher needs nothing beside it.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
add_executable(yougame-sandbox launcher.cpp)
target_compile_definitions(yougame-sandbox PRIVATE UNICODE _UNICODE NOMINMAX)
target_compile_options(yougame-sandbox PRIVATE /utf-8 /W4)
target_link_libraries(yougame-sandbox PRIVATE userenv advapi32)
add_executable(sandbox-probe probe.cpp)
target_compile_definitions(sandbox-probe PRIVATE NOMINMAX)
target_link_libraries(sandbox-probe PRIVATE ws2_32 user32 gdi32 advapi32)
install(TARGETS yougame-sandbox RUNTIME DESTINATION .)
