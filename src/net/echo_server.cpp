#include "net/echo_server.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include <iostream>
#include <fstream>
#include <unordered_map>
#include <unordered_set>

namespace
{

    // 简单的连接输出缓冲；生产环境请换循环缓冲区
    static std::unordered_map<int, std::string> g_outbuf;
    // 读取缓冲：每个连接累计请求头
    static std::unordered_map<int, std::string> g_inbuf;
    // 写完后是否关闭连接（当对方/我们要求 Connection: close）
    static std::unordered_map<int, bool> g_close_after_write;
    // WebSocket升级标记 fd 是否已经升级成 WebSocket
    static std::unordered_map<int, bool> g_is_websocket;
    // 维护一个客户端集合
    static std::unordered_set<int> g_ws_clients;

    // 状态码字典
    static const std::unordered_map<int, std::string> REASON = {
        {200, "OK"},
        {400, "Bad Request"},
        {401, "Unauthorized"},
        {404, "Not Found"},
        {500, "Internal Server Error"},
    };

    // 用 OpenSSL EVP_EncodeBlock 做 Base64 编码
    std::string base64_encode(const unsigned char *data, size_t len)
    {
        // Base64 输出长度大约是 4 * ((len + 2) / 3)
        std::string out;
        out.resize(4 * ((len + 2) / 3));

        int out_len = EVP_EncodeBlock(
            reinterpret_cast<unsigned char *>(&out[0]),
            data,
            static_cast<int>(len));
        if (out_len < 0)
            return {};

        out.resize(out_len); // 修正为真实长度
        return out;
    }

    // 计算 WebSocket 的 Sec-WebSocket-Accept
    std::string ws_accept_key(const std::string &client_key)
    {
        static const std::string kGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

        std::string src = client_key + kGUID;

        // 1. SHA1
        unsigned char sha[SHA_DIGEST_LENGTH];
        SHA1(reinterpret_cast<const unsigned char *>(src.data()), src.size(), sha);

        // 2. Base64
        return base64_encode(sha, SHA_DIGEST_LENGTH);
    }

} // namespace

EchoServer::EchoServer(int port) : port_(port) {}

void EchoServer::set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

void EchoServer::set_reuseaddr(int fd)
{
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
#ifdef SO_REUSEPORT
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes));
#endif
}

void EchoServer::add_fd(int epfd, int fd, uint32_t events)
{
    epoll_event ev{};
    ev.events = events;
    ev.data.fd = fd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0)
    {
        perror("epoll_ctl ADD");
    }
}

void EchoServer::mod_fd(int epfd, int fd, uint32_t events)
{
    epoll_event ev{};
    ev.events = events;
    ev.data.fd = fd;
    if (epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev) < 0)
    {
        perror("epoll_ctl MOD");
    }
}

void EchoServer::del_fd(int epfd, int fd)
{
    epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nullptr);
}

void EchoServer::close_conn(int fd)
{
    del_fd(epfd_, fd);
    g_outbuf.erase(fd);
    g_inbuf.erase(fd);
    g_close_after_write.erase(fd);
    g_is_websocket.erase(fd);
    g_ws_clients.erase(fd);
    ::close(fd);
}

// 提取首行: "GET /path HTTP/1.1"
bool EchoServer::parse_request_line(const std::string &header, std::string &method, std::string &path, std::string &version)
{
    // header 是从开头到 \r\n 之前
    auto sp1 = header.find(' ');
    if (sp1 == std::string::npos)
        return false;
    auto sp2 = header.find(' ', sp1 + 1);
    if (sp2 == std::string::npos)
        return false;
    method = header.substr(0, sp1);
    path = header.substr(sp1 + 1, sp2 - sp1 - 1);
    version = header.substr(sp2 + 1);
    return true;
}

std::string EchoServer::make_http_response(const int status, const std::string &content_type, const std::string &body, bool keep_alive)
{
    // 1. 状态码 -> reason phrase
    auto it = REASON.find(status);
    std::string reason = (it != REASON.end()) ? it->second : "OK";

    // 2. 构造响应
    std::string res;
    res += "HTTP/1.1 " + std::to_string(status) + " " + reason + "\r\n";
    res += "Content-Type: " + content_type + "\r\n";
    res += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    if (keep_alive)
    {
        res += "Connection: keep-alive\r\n";
    }
    else
    {
        res += "Connection: close\r\n";
    }
    res += "\r\n";
    res += body;
    return res;
}

void EchoServer::queue_response(int fd, int status, const std::string &content_type, const std::string &body, bool keep_alive)
{
    std::string resp = make_http_response(status, content_type, body, keep_alive);
    g_outbuf[fd] += resp;
    g_close_after_write[fd] = !keep_alive;
    mod_fd(epfd_, fd, EPOLLIN | EPOLLOUT);
}

std::string EchoServer::extract_json_field(const std::string &body, const std::string &key)
{
    // 假设格式是 {"key":"value",...}
    std::string pat = "\"" + key + "\"";
    auto pos = body.find(pat);
    if (pos == std::string::npos)
        return "";

    pos = body.find(':', pos + pat.size());
    if (pos == std::string::npos)
        return "";

    // 跳过冒号和可能的空格
    ++pos;
    while (pos < body.size() && (body[pos] == ' ' || body[pos] == '\"'))
        ++pos;

    // 收集值字符，直到结束符
    std::string val;
    while (pos < body.size() && body[pos] != '\"' && body[pos] != ',' && body[pos] != '}')
    {
        val.push_back(body[pos]);
        ++pos;
    }
    return val;
}

bool EchoServer::get_header_value(const std::string &header, const std::string &key, std::string &value_out)
{
    // 例如 "Content-Length:" 或 "Sec-WebSocket-Key:"
    std::string prefix = key + ":";
    size_t start = 0;
    while (true)
    {
        size_t end = header.find("\r\n", start);
        if (end == std::string::npos)
            break;
        std::string line = header.substr(start, end - start);

        // 这里只匹配以 prefix 开头的行
        if (line.rfind(prefix, 0) == 0)
        {
            // 拿冒号后面的内容
            std::string val = line.substr(prefix.size());
            // 去掉前面的空格
            size_t p = 0;
            while (p < val.size() && (val[p] == ' ' || val[p] == '\t'))
                ++p;
            val = val.substr(p);
            value_out = val;
            return true;
        }
        start = end + 2;
    }
    return false;
}

// 升级Webserve
bool EchoServer::is_websocket_handshake(const std::string &method, const std::string &path, const std::string &header, std::string &client_key_out)
{
    if (method != "GET")
        return false;
    if (path.rfind("/chat", 0) != 0)
        return false;

    // 必须有 Sec-WebSocket-Key
    std::string key;
    if (!get_header_value(header, "Sec-WebSocket-Key", key))
        return false;
    client_key_out = key;
    return true;
}

// Webserve - 构造帧
std::string EchoServer::make_ws_text_frame(const std::string &msg)
{
    std::string frame;

    if (msg.size() > 125)
    {
        // 以后再扩展 126/127 的情况
    }

    unsigned char b1 = 0x81;                                   // FIN=1, TEXT
    unsigned char b2 = static_cast<unsigned char>(msg.size()); // MASK=0 + len

    frame.push_back(static_cast<char>(b1));
    frame.push_back(static_cast<char>(b2));
    frame.append(msg);

    return frame;
}

// Webserve - 发送帧
void EchoServer::send_ws_text(int fd, const std::string &msg)
{
    std::string frame = make_ws_text_frame(msg);

    g_outbuf[fd] += frame;
    g_close_after_write[fd] = false; // WebSocket 长连接，不主动关
    mod_fd(epfd_, fd, EPOLLIN | EPOLLOUT);
}

// 广播函数：给所有 WebSocket 客户端发消息
void EchoServer::broadcast_ws_text(const std::string &msg)
{
    for (int cfd : g_ws_clients)
    {
        // 每个客户端单独发一帧
        send_ws_text(cfd, msg);
    }
}

void EchoServer::init_listen()
{
    listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0)
    {
        perror("socket");
        std::exit(1);
    }
    set_reuseaddr(listen_fd_);
    set_nonblock(listen_fd_);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(listen_fd_, (sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind");
        std::exit(1);
    }
    // backlog 设大一些避免突发连接被拒
    if (listen(listen_fd_, 1024) < 0)
    {
        perror("listen");
        std::exit(1);
    }
}

void EchoServer::init_epoll()
{
    epfd_ = epoll_create1(EPOLL_CLOEXEC);
    if (epfd_ < 0)
    {
        perror("epoll_create1");
        std::exit(1);
    }
    // 先用 LT（Level-Triggered）模式更易调试；稳定后再切 ET
    add_fd(epfd_, listen_fd_, EPOLLIN);
}

void EchoServer::handle_accept()
{
    while (true)
    {
        sockaddr_in cli{};
        socklen_t len = sizeof(cli);
        int cfd = accept4(listen_fd_, (sockaddr *)&cli, &len, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (cfd < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                // 没有更多连接
                break;
            }
            else if (errno == EINTR)
            {
                continue;
            }
            else
            {
                perror("accept4");
                break;
            }
        }
        add_fd(epfd_, cfd, EPOLLIN); // 先关注读事件
        // 可选打印：新连接
        /*
        std::cerr << "accept fd=" << cfd << "\n";
        */
    }
}

void EchoServer::handle_read(int fd)
{
    char buf[4096];

    while (true)
    {
        ssize_t n = ::read(fd, buf, sizeof(buf));
        if (n > 0)
        {
            g_inbuf[fd].append(buf, (size_t)n);
            // ---- 1 ---- //

            // ---- webserve 逻辑 ---- //
            if (g_is_websocket[fd])
            {
                handle_websocket_read(fd);
                return;
            }

            // ---- HTTP 逻辑 ---- //
            // 处理请求头（到 \r\n\r\n 为止）；还没收全就等下一次 EPOLLIN
            auto pos = g_inbuf[fd].find("\r\n\r\n");
            if (pos == std::string::npos)
            {
                continue; // 继续读，或等下一轮可读
            }

            // 取出请求头文本
            std::string header = g_inbuf[fd].substr(0, pos + 2); // \r\n 之前的首行和头
            size_t header_end = pos + 4;                         // header 结束后 body 起始位置
            // 解析首行
            std::string first_line;
            {
                auto rn = header.find("\r\n");
                first_line = (rn == std::string::npos) ? header : header.substr(0, rn);
            }
            std::string method, path, version;
            int status = 200;
            if (!parse_request_line(first_line, method, path, version))
            {
                // 非法请求，简单返回 400
                queue_response(fd, 400, "text/plain", "", false); // 直接关连接

                close_conn(fd);
                return;
            }

            // ---- 2 ---- //

            // 尝试识别 WebSocket 握手
            std::string ws_key;
            if (is_websocket_handshake(method, path, header, ws_key))
            {
                std::string accept_val = ws_accept_key(ws_key);

                std::string resp;
                resp = "HTTP/1.1 101 Switching Protocols\r\n";
                resp += "Upgrade: websocket\r\n";
                resp += "Connection: Upgrade\r\n";
                resp += "Sec-WebSocket-Accept: " + accept_val + "\r\n";
                resp += "\r\n";

                g_outbuf[fd] += resp;
                g_close_after_write[fd] = false; // WebSocket 要保持连接
                g_is_websocket[fd] = true;       // 标记为 WebSocket 连接
                mod_fd(epfd_, fd, EPOLLIN | EPOLLOUT);
                g_inbuf[fd].erase(0, header_end);

                // 加入 WS 客户端集合
                g_ws_clients.insert(fd);
                // 这一条请求就到此为止，不再走 HTTP /login 路由
                continue;
            }

            // 判断是否有 POST 或 GET 请求...
            std::string resp_body;
            std::string pure_path = path;
            std::string name;
            if (method == "GET")
            {
                // 解析查询参数，例如 /hello?name=tom
                std::string query;

                auto pos_q = path.find('?');
                if (pos_q != std::string::npos)
                {
                    pure_path = path.substr(0, pos_q); // /hello
                    query = path.substr(pos_q + 1);    // name=tom
                }
                name = "anonymous";
                if (!query.empty())
                {
                    auto pos_name = query.find("name=");
                    if (pos_name != std::string::npos)
                    {
                        auto start = pos_name + 5; // 跳过 "name="
                        auto end = query.find('&', start);
                        if (end == std::string::npos)
                            end = query.size();
                        name = query.substr(start, end - start);
                    }
                }
                g_inbuf[fd].erase(0, header_end);
            }
            else if (method == "POST")
            {
                int content_length = 0;
                std::string value;
                if (!get_header_value(header, "Content-Length", value))
                {
                    // 没有 Content-Length：这个 POST 我们不认，直接 400
                    queue_response(fd, 400,
                                   "application/json",
                                   R"({"error":"missing Content-Length"})",
                                   false);
                    close_conn(fd);
                    return;
                }
                try
                {
                    content_length = std::stoi(value);
                }
                catch (...)
                {
                    // 非数字，也当 Bad Request
                    queue_response(fd, 400,
                                   "application/json",
                                   R"({"error":"invalid Content-Length"})",
                                   false);
                    close_conn(fd);
                    return;
                }

                if (content_length <= 0)
                {
                    // 对于 /login 这样的接口，空 body 基本就是错误，用 400 比较合理
                    queue_response(fd, 400,
                                   "application/json",
                                   R"({"error":"invalid Content-Length"})",
                                   false);
                    close_conn(fd);
                    return;
                }

                // g_inbuf[fd] 现在至少包含 0 ~ content_length 字节 body，可能还不全
                // 当前 body 已收到的字节数
                size_t have_body = g_inbuf[fd].size() - (header_end);

                if (have_body < (size_t)content_length)
                {
                    // 头还留在 inbuf 里，下次再一起用
                    return;
                }

                // 这时说明 header + body 都完整到了
                std::string body = g_inbuf[fd].substr(header_end, content_length);
                // 再一次性把 header+body 从 inbuf 擦掉：
                g_inbuf[fd].erase(0, header_end + content_length);

                std::string user = extract_json_field(body, "user");
                std::string pass = extract_json_field(body, "password");
                std::cerr << "[LOGIN] user=" << user << " pass=" << pass << "\n";
                bool ok = (user == "huolong" && pass == "123456");

                if (ok)
                {
                    resp_body = R"({"token": "fake-token-123"})";
                }
                else
                {
                    status = 401;
                    resp_body = R"({"error": "invalid credentials"})";
                }
            }
            // 5) 是否 keep-alive：HTTP/1.1 默认 keep-alive，若头里带 close 就关闭
            bool keep_alive = (version == "HTTP/1.1");
            if (header.find("Connection: close") != std::string::npos ||
                header.find("connection: close") != std::string::npos)
            {
                keep_alive = false;
            }

            // 构造响应体
            std::string body;
            std::string content_type = "text/html; charset=utf-8";
            // 路由
            if (pure_path == "/" && method == "GET")
            {
                // 读取 chat.html
                std::string file_path = doc_root_ + "/chat.html";

                std::ifstream ifs(file_path);
                if (!ifs)
                {
                    // 文件不存在时返回 404
                    body = "404 Not Found";
                    content_type = "text/plain";
                    status = 404;
                }
                else
                {
                    // 读取整个文件内容
                    body.assign((std::istreambuf_iterator<char>(ifs)),
                                std::istreambuf_iterator<char>());
                    content_type = "text/html; charset=utf-8";
                    status = 200;
                }
            }

            else if (pure_path == "/ping")
            {
                body = R"({"msg": "pong"})"; // 原始字符串字面量
                content_type = "application/json";
            }
            else if (pure_path == "/hello")
            {
                body = R"({"msg": "hello, )" + name + R"("})";
                content_type = "application/json";
            }
            else if (pure_path == "/login" && method == "POST")
            {
                // resp_body是前面处理过login时的token
                body = resp_body;
                content_type = "application/json";
            }
            else
            {
                body = R"({"error": "not found"})";
                content_type = "application/json";
                status = 404;
            }

            /*
            std::cerr << "[DEBUG RESP] status=" << status
                      << " path=" << pure_path
                      << " method=" << method
                      << " body='" << body << "' (len=" << body.size() << ")\n";
                      */

            queue_response(fd, status, content_type, body, keep_alive);
        }
        else if (n == 0)
        {
            // 对端关闭
            close_conn(fd);
            break;
        }
        else
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            if (errno == EINTR)
                continue;
            close_conn(fd);
            break;
        }
    }
}

void EchoServer::handle_websocket_read(int fd)
{
    auto &buf = g_inbuf[fd];

    // 1) 确保至少有 2 字节头
    if (buf.size() < 2)
    {
        return; // 等下次数据再来
    }

    /*
    std::cerr << "[WS RAW] size=" << buf.size() << " bytes: ";
    for (size_t i = 0; i < buf.size() && i < 40; ++i)
    {
        unsigned char ch = static_cast<unsigned char>(buf[i]);
        std::cerr << std::hex << (int)ch << " ";
    }
    std::cerr << std::dec << "\n";
    */

    unsigned char b1 = static_cast<unsigned char>(buf[0]);
    unsigned char b2 = static_cast<unsigned char>(buf[1]);

    bool fin = (b1 & 0x80) != 0; // 1000 0000
    int opcode = b1 & 0x0F;      // 0000 1111

    bool masked = (b2 & 0x80) != 0;     // 1000 0000
    uint64_t payload_len = (b2 & 0x7F); // 0111 1111

    // 在这里先打印一下这些字段，确认解析正确
    /*
    std::cerr << "[WS] fd=" << fd
    << " fin=" << fin
    << " opcode=" << opcode
    << " masked=" << masked
    << " payload_len=" << payload_len
    << " buf_size=" << buf.size()
    << "\n";
    */

    // 客户端到服务器必须有 mask，否则就是协议错误
    if (!masked)
    {
        std::cerr << "[WS] unmasked frame from client, close.\n";
        close_conn(fd); // 你已有的工具函数 :contentReference[oaicite:0]{index=0}
        return;
    }

    // 目前只支持 payload_len <= 125，且不考虑 126/127 的扩展长度
    if (payload_len > 125)
    {
        std::cerr << "[WS] payload_len > 125 not supported yet, close.\n";
        close_conn(fd);
        return;
    }

    // 计算这一帧最少需要的总字节数：2(头) + 4(mask-key) + payload_len
    size_t frame_min_size = 2 + 4 + static_cast<size_t>(payload_len);
    if (buf.size() < frame_min_size)
    {
        // 一帧还没收全，等下次 EPOLLIN
        return;
    }

    // 从 buf 中解析这一帧
    size_t idx = 2; // 前两个字节已经是 b1,b2

    unsigned char mask_key[4];
    for (int i = 0; i < 4; ++i)
    {
        mask_key[i] = static_cast<unsigned char>(buf[idx + i]);
    }
    idx += 4;

    // 取出被 mask 过的 payload
    std::string decoded;
    decoded.reserve(static_cast<size_t>(payload_len));

    for (size_t i = 0; i < payload_len; ++i)
    {
        unsigned char m = static_cast<unsigned char>(buf[idx + i]);
        unsigned char k = mask_key[i % 4];
        unsigned char c = m ^ k; // 解码
        decoded.push_back(static_cast<char>(c));
    }

    // 打印解码后的文本内容
    std::cerr << "[WS] decoded text: '" << decoded << "'\n";

    // 广播客户端
    broadcast_ws_text(decoded);

    // 把这一帧从缓冲区里移除
    buf.erase(0, frame_min_size);

    // TODO: 以后可以在这里 while(buf.size() >= 2) 再尝试解析下一帧
}

void EchoServer::handle_write(int fd)
{
    auto it = g_outbuf.find(fd);
    if (it == g_outbuf.end() || it->second.empty())
    {
        // 没有要写的了，取消 EPOLLOUT
        mod_fd(epfd_, fd, EPOLLIN);
        return;
    }
    std::string &out = it->second;
    while (!out.empty())
    {
        ssize_t n = ::write(fd, out.data(), out.size());
        if (n > 0)
        {
            out.erase(0, (size_t)n);
        }
        else if (n < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                // 写满了，等下次可写
                break;
            }
            if (errno == EINTR)
                continue;
            // 其他错误：关闭
            close_conn(fd);
            return;
        }
        else
        {
            // n==0 几乎不会发生在写；保守处理为退出
            break;
        }
    }
    // 如果写完了，去掉 EPOLLOUT，必要时关闭
    if (out.empty())
    {
        if (g_close_after_write[fd])
        {
            close_conn(fd);
            return;
        }
        mod_fd(epfd_, fd, EPOLLIN);
    }
}

void EchoServer::run()
{
    init_listen();
    init_epoll();

    constexpr int MAX_EVENTS = 1024;
    epoll_event events[MAX_EVENTS];

    std::cout << "EchoServer running on 0.0.0.0:" << port_ << " (LT, single-thread)\n";

    while (true)
    {
        int n = epoll_wait(epfd_, events, MAX_EVENTS, -1);
        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            perror("epoll_wait");
            break;
        }
        for (int i = 0; i < n; ++i)
        {
            int fd = events[i].data.fd;
            uint32_t ev = events[i].events;

            if (fd == listen_fd_)
            {
                handle_accept();
                continue;
            }
            if (ev & (EPOLLHUP | EPOLLERR))
            {
                close_conn(fd);
                continue;
            }
            if (ev & EPOLLIN)
                handle_read(fd);
            if (ev & EPOLLOUT)
                handle_write(fd);
        }
    }

    ::close(listen_fd_);
    ::close(epfd_);
}
