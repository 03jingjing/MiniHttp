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
#include <unordered_map>

namespace
{
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

// 简单的连接输出缓冲；生产环境请换循环缓冲区
static std::unordered_map<int, std::string> g_outbuf;

// 读取缓冲：每个连接累计请求头
static std::unordered_map<int, std::string> g_inbuf;
// 写完后是否关闭连接（当对方/我们要求 Connection: close）
static std::unordered_map<int, bool> g_close_after_write;

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
    ::close(fd);
}

// 提取首行: "GET /path HTTP/1.1"
bool EchoServer::parse_request_line(const std::string &header,
                                    std::string &method,
                                    std::string &path,
                                    std::string &version)
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

// 构造 HTTP 响应
std::string EchoServer::make_http_response(const int status,
                                           const std::string &content_type,
                                           const std::string &body,
                                           bool keep_alive)
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

std::string EchoServer::extract_json_field(const std::string &body,
                                           const std::string &key)
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

bool EchoServer::get_header_value(const std::string &header,
                                  const std::string &key,
                                  std::string &value_out)
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

// 统一发送HTTP响应
void EchoServer::queue_response(int fd,
                                int status,
                                const std::string &content_type,
                                const std::string &body,
                                bool keep_alive)
{
    std::string resp = make_http_response(status, content_type, body, keep_alive);
    g_outbuf[fd] += resp;
    g_close_after_write[fd] = !keep_alive;
    mod_fd(epfd_, fd, EPOLLIN | EPOLLOUT);
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
            // 1) 累加到该连接的输入缓冲
            g_inbuf[fd].append(buf, (size_t)n);

            // 2) 只处理请求头（到 \r\n\r\n 为止）；还没收全就等下一次 EPOLLIN
            auto pos = g_inbuf[fd].find("\r\n\r\n");
            if (pos == std::string::npos)
            {
                continue; // 继续读，或等下一轮可读
            }

            // 3) 取出请求头文本
            std::string header = g_inbuf[fd].substr(0, pos + 2); // \r\n 之前的首行和头
            g_inbuf[fd].erase(0, pos + 4);                       // 丢掉整个 header（含 \r\n\r\n）

            // 4) 解析首行
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
                queue_response(fd,
                               400,
                               "text/plain",
                               "",     // 没 body
                               false); // 直接关连接
                continue;
            }
            std::string resp_body;
            std::string pure_path = path;
            std::string name;
            if (method == "POST")
            {
                int content_length = 0;
                std::string value;
                if (!get_header_value(header, "Content-Length", value))
                {
                    // 没有 Content-Length：这个 POST 我们不认，直接 400
                    queue_response(
                        fd,
                        400,
                        "application/json",
                        R"({"error":"missing Content-Length"})",
                        false);
                    return;
                }
                try
                {
                    content_length = std::stoi(value);
                }
                catch (...)
                {
                    // 非数字，也当 Bad Request
                    queue_response(
                        fd,
                        400,
                        "application/json",
                        R"({"error":"invalid Content-Length"})",
                        false);
                    return;
                }

                if (content_length <= 0)
                {
                    // 对于 /login 这样的接口，空 body 基本就是错误，用 400 比较合理
                    queue_response(
                        fd,
                        400,
                        "application/json",
                        R"({"error":"invalid Content-Length"})",
                        false);
                    return;
                }

                // 删掉 header 之后
                // g_inbuf[fd] 现在至少包含 0 ~ content_length 字节 body，可能还不全
                if (g_inbuf[fd].size() < (size_t)content_length)
                {
                    // 还没收够 body，先返回，等下一次 EPOLLIN 再读
                    return;
                }

                // 保存body
                std::string body = g_inbuf[fd].substr(0, content_length);
                // 把 body 从 inbuf 里删掉
                g_inbuf[fd].erase(0, content_length);

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
            else if (method == "GET")
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
            }
            // 5) 是否 keep-alive：HTTP/1.1 默认 keep-alive，若头里带 close 就关闭
            bool keep_alive = (version == "HTTP/1.1");
            if (header.find("Connection: close") != std::string::npos ||
                header.find("connection: close") != std::string::npos)
            {
                keep_alive = false;
            }

            // 6) 构造响应体（这里固定返回一个简单页面；可根据 path 定制）
            std::string body;
            std::string content_type = "text/html; charset=utf-8";
            // 简单路由
            if (pure_path == "/")
            {
                // 返回首页 HTML
                body = "<html>...</html>";
                content_type = "text/html; charset=utf-8";
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
