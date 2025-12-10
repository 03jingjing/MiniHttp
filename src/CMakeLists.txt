# src/CMakeLists.txt
set(SRC_FILES
    main.cpp
    net/echo_server.cpp

    # 以后加：net/epoller.cpp http/parser.cpp util/logger.cpp ...
)

add_executable(minihttp ${SRC_FILES})
target_include_directories(minihttp PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src)

# 把顶层的 PROJECT_VERSION 传给代码使用
target_compile_definitions(minihttp PRIVATE PROJECT_VERSION="${PROJECT_VERSION}")

find_package(OpenSSL REQUIRED)

target_link_libraries(minihttp PRIVATE OpenSSL::SSL OpenSSL::Crypto)
