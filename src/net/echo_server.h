#pragma once
#include <string>
#include <cstdint>

class EchoServer
{
public:
    explicit EchoServer(int port = 8080);
    // 阻塞运行事件循环（单线程）
    void run();

private:
    int listen_fd_ = -1;
    int epfd_ = -1;
    int port_ = 8080;
    std::string doc_root_ = "./www"; // 前端文件路径

    // 初始化监听 socket 与 epoll
    void init_listen();
    void init_epoll();

    // 事件处理
    void handle_accept();
    void handle_read(int fd);
    void handle_write(int fd);

    // WebSocket 帧读取/处理
    void handle_websocket_read(int fd);

    // 工具
    // 把 fd 设成非阻塞：read/write 立刻返回，没数据时 errno=EAGAIN
    static void set_nonblock(int fd);
    // SO_REUSEADDR/PORT，端口复用，避免 TIME_WAIT 绑定失败
    static void set_reuseaddr(int fd);
    // epoll_ctl(ADD...)，把fd加入epoll关注
    static void add_fd(int epfd, int fd, uint32_t events);
    // epoll_ctl(MOD...)，修改fd关注的事件集合
    static void mod_fd(int epfd, int fd, uint32_t events);
    // epoll_ctl(DEL...)，从epoll移除
    static void del_fd(int epfd, int fd);
    // 关闭连接清理缓存区
    void close_conn(int fd);
    // 提取首行: "GET /path HTTP/1.1"
    static bool parse_request_line(const std::string &header,
                                   std::string &method,
                                   std::string &path,
                                   std::string &version);
    // 构造HTTP响应
    std::string make_http_response(const int status,
                                   const std::string &content_type,
                                   const std::string &body,
                                   bool keep_alive);
    // 发送HTTP响应
    void queue_response(int fd,
                        int status,
                        const std::string &content_type,
                        const std::string &body,
                        bool keep_alive);
    // 解析body
    static std::string extract_json_field(const std::string &body,
                                          const std::string &key);

    // 从完整 header 文本中找到某一行 "Key: Value" 并返回 Value（去掉前后空格）
    static bool get_header_value(const std::string &header,
                                 const std::string &key,
                                 std::string &value_out);
    // 升级webserve
    static bool is_websocket_handshake(const std::string &method,
                                       const std::string &path,
                                       const std::string &header,
                                       std::string &client_key_out);
    // Webserve - 构造帧
    std::string make_ws_text_frame(const std::string &msg);
    // Webserve - 发送帧
    void send_ws_text(int fd, const std::string &msg);
    // 广播函数：给所有 WebSocket 客户端发消息
    void broadcast_ws_text(const std::string &msg);
};
