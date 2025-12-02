#include "net/echo_server.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <iostream>
#include <unordered_map>

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

// 构造最小 HTTP 响应
std::string EchoServer::make_http_response(const std::string &body,
                                           const std::string &content_type,
                                           bool keep_alive)
{
    std::string res;
    res += "HTTP/1.1 200 OK\r\n";
    res += "Content-Type: " + std::to_string(content_type.size())+ "\r\n";
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
        // std::cerr << "accept fd=" << cfd << "\n";
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
            // 我们这个最小版忽略 body（只处理 GET）

            // 4) 解析首行
            std::string first_line;
            {
                auto rn = header.find("\r\n");
                first_line = (rn == std::string::npos) ? header : header.substr(0, rn);
            }
            std::string method, path, version;
            if (!parse_request_line(first_line, method, path, version))
            {
                // 非法请求，简单返回 400
                std::string bad = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
                g_outbuf[fd] += bad;
                g_close_after_write[fd] = true;
                mod_fd(epfd_, fd, EPOLLIN | EPOLLOUT);
                continue;
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
            if (path == "/")
            {
                body =
                    "<!doctype html><html><body>"
                    "<h3>MiniHTTP is running 🎯</h3>"
                    "<p>Method: " +
                    method + " Path: " + path + "</p>"
                                                "</body></html>";
                content_type = "text/html; charset=utf-8";
            }
            else if (path == "/ping")
            {
                body = R"({"msg": "pong"})"; // 原始字符串字面量
                content_type = "application/json";
            }
            else
            {
                body = R"({"error": "not found"})";
                content_type = "application/json";
                // 这里其实应该返回 404 状态码，先偷懒返回 200 OK
            }

            std::string resp = make_http_response(body, content_type, keep_alive);
            g_outbuf[fd] += resp;
            g_close_after_write[fd] = !keep_alive;

            // 7) 关心可写，把响应发出去
            mod_fd(epfd_, fd, EPOLLIN | EPOLLOUT);
        }
        else if (n == 0)
        {
            // 对端关闭
            del_fd(epfd_, fd);
            g_outbuf.erase(fd);
            g_inbuf.erase(fd);
            g_close_after_write.erase(fd);
            ::close(fd);
            break;
        }
        else
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            if (errno == EINTR)
                continue;
            del_fd(epfd_, fd);
            g_outbuf.erase(fd);
            g_inbuf.erase(fd);
            g_close_after_write.erase(fd);
            ::close(fd);
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
            del_fd(epfd_, fd);
            g_outbuf.erase(fd);
            ::close(fd);
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
            del_fd(epfd_, fd);
            g_outbuf.erase(fd);
            g_inbuf.erase(fd);
            g_close_after_write.erase(fd);
            ::close(fd);
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
                del_fd(epfd_, fd);
                g_outbuf.erase(fd);
                ::close(fd);
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
