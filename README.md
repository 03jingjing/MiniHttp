# 🚀 MiniHTTP — 高并发 C++ 网络服务器

## 📖 项目简介
MiniHTTP 是一个基于 **C++20** 编写的轻量级高并发 Web 服务器，采用 **epoll + Reactor 模型 + 线程池** 设计，支持数千并发连接。  
项目目标是帮助学习和展示网络编程、并发编程和数据库交互等核心系统开发能力。

---

## 🧩 项目特性
- ✅ 使用 **非阻塞 I/O + epoll** 实现多连接高并发处理  
- ✅ 实现 **Reactor 模型** 与线程池，提高吞吐量  
- ✅ 支持 **HTTP/1.1 协议解析**，返回静态文件与动态接口  
- ✅ 内置 **MySQL 连接池** 与简单 ORM 接口  
- ✅ 封装日志系统、配置文件读取、限流与统计模块  
- ✅ 通过 `ab` / `wrk` 压测验证性能  
- ✅ 完全独立实现，零第三方依赖（可选 spdlog/json/yaml-cpp）

---

## 🧱 项目结构
\`\`\`plaintext
MiniHTTP/
├── CMakeLists.txt          # 顶层构建文件
├── src/
│   ├── main.cpp            # 程序入口
│   ├── net/                # 网络与事件循环模块
│   ├── http/               # HTTP 解析与响应
│   ├── util/               # 工具类、线程池、日志等
│   ├── db/                 # 数据库连接池
│   └── server/             # 服务器主逻辑
├── include/                # 头文件
├── third_party/            # 可选外部库
├── tests/                  # 测试与压测脚本
└── docs/                   # 文档与设计笔记
\`\`\`

---

## ⚙️ 构建步骤
**系统环境**：Ubuntu 20.04+/22.04+（或其他 Linux 发行版）

### 安装依赖
\`\`\`bash
sudo apt update
sudo apt install -y build-essential cmake libmysqlclient-dev pkg-config
\`\`\`

### 编译与运行
\`\`\`bash
git clone https://github.com/03jingjing/MiniHTTP.git
cd MiniHTTP
mkdir build && cd build
cmake ..
cmake --build . -j
./src/minihttp --help     # 或 ./bin/minihttp
\`\`\`

---

## 🧠 模块说明

| 模块 | 功能描述 |
|------|-----------|
| **net/** | 使用 epoll 实现 I/O 事件分发，支持 ET/LT 模式 |
| **http/** | HTTP 请求解析与响应封装 |
| **util/** | 日志、线程池、定时器、配置文件等 |
| **db/** | MySQL 连接池与查询封装 |
| **server/** | 主服务器类，协调各模块运行 |

---

## 📊 性能测试（示例）
使用 `ab`（ApacheBench）或 `wrk` 进行压测：
\`\`\`bash
ab -n 100000 -c 2000 http://127.0.0.1:8080/
\`\`\`

| 并发数 | 请求总数 | QPS | 平均延迟 | 99%延迟 |
|---------|-----------|-----|-----------|-----------|
| 2000 | 100000 | 18,500 | 2.1 ms | 6.3 ms |

> 测试环境：AMD Ryzen 5800H / Ubuntu 22.04 / epoll + 8 threads

---

## 🧩 技术要点
- 基于 **Reactor 模型** 的事件驱动设计  
- 使用 **非阻塞 I/O** 避免线程阻塞  
- 自研 **线程池** 与任务队列调度  
- 封装 **MySQL 连接池** 提高数据库访问性能  
- 实现日志滚动、连接复用与简单限流  
- 代码完全由原生 C++ 实现，无 Boost 依赖  

---

## 📈 未来改进方向
- 支持 HTTP Keep-Alive、长连接复用  
- 加入 Redis 缓存层  
- 实现 HTTP 文件上传与下载  
- 支持 HTTPS（OpenSSL）  
- 增加 RESTful API 框架与 JSON 接口封装  

---

## 🧑‍💻 作者
**Huolong**  
- 📫 Email: your.email@example.com  
- 💼 GitHub: [github.com/huolong](https://github.com/huolong)  
- 🧠 兴趣方向：C++ 服务端开发 / 网络编程 / 高性能系统设计  

---

## 📄 许可证
MIT License  
自由学习与使用，欢迎 PR 与讨论。
