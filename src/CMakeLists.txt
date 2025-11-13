# src/CMakeLists.txt
set(SRC_FILES
    main.cpp
    # 以后加：net/epoller.cpp http/parser.cpp util/logger.cpp ...
)

add_executable(minihttp ${SRC_FILES})
target_include_directories(minihttp PRIVATE ${CMAKE_SOURCE_DIR}/include)

# 把顶层的 PROJECT_VERSION 传给代码使用
target_compile_definitions(minihttp PRIVATE PROJECT_VERSION="${PROJECT_VERSION}")
