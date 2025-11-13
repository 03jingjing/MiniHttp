cmake_minimum_required(VERSION 3.16)
project(MiniHTTP VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# 默认较严格的警告
add_compile_options(-Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wno-unused-parameter)
# 开启调试+优化（后面压测再切换 -O2/-O3）
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

add_subdirectory(src)   # 交给 src/CMakeLists.txt 生成可执行文件

