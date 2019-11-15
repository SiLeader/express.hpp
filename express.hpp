//
// Created by cerussite on 2019/11/15.
//

#ifndef CXXREST_EXPRESS_HPP
#define CXXREST_EXPRESS_HPP

#include <functional>
#include <iostream>
#include <regex>

#include <sys/epoll.h>

#include <arpa/nameser_compat.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unordered_map>
#include <zconf.h>

#define REST_HTTP_NEWLINE "\r\n"

namespace express {
    enum class Method {
        GET,
        POST,
        PUT,
        DEL,
    };

    namespace detail {
        std::string statusCode(int s);
        struct RequestHeader {
        private:
            Method _method;
            std::string _path;
            std::unordered_map<std::string, std::string> _kv;

        private:
            static std::vector<std::string> Split(const std::string &string,
                                                  const std::string &separator) {
                auto list = std::vector<std::string>();
                auto separator_length = separator.size();

                if (separator_length == 0) {
                    list.push_back(string);
                } else {
                    auto offset = std::string::size_type(0);
                    while (1) {
                        auto pos = string.find(separator, offset);
                        if (pos == std::string::npos) {
                            list.push_back(string.substr(offset));
                            break;
                        }
                        list.push_back(string.substr(offset, pos - offset));
                        offset = pos + separator_length;
                    }
                }

                return list;
            }
            static std::string Lower(const std::string &s) {
                std::string str(s.size(), 0);
                std::transform(std::begin(s), std::end(s), std::begin(str), ::tolower);
                return str;
            }

            static std::string Trim(const std::string &string,
                                    const char *trimCharacterList = " \t\v\r\n") {
                std::string result;
                std::string::size_type left = string.find_first_not_of(trimCharacterList);

                if (left != std::string::npos) {
                    std::string::size_type right = string.find_last_not_of(trimCharacterList);
                    result = string.substr(left, right - left + 1);
                }
                return result;
            }

        public:
            RequestHeader(Method method, std::string path,
                          std::unordered_map<std::string, std::string> kv)
                : _method(method)
                , _path(std::move(path))
                , _kv(std::move(kv)) {}

            static RequestHeader Parse(const std::string &header) {
                Method method;
                std::string path;
                std::unordered_map<std::string, std::string> kv;

                auto lines = Split(header, REST_HTTP_NEWLINE);
                auto top = Split(lines[0], " ");

                const auto &methodStr = top[0];
#define METHOD_ADD(m)                                                                              \
    if (methodStr == #m) {                                                                         \
        method = Method::m;                                                                        \
    }
                METHOD_ADD(GET)
                else METHOD_ADD(POST) else METHOD_ADD(PUT) else if (methodStr == "DELETE") {
                    method = Method::DEL;
                }
#undef METHOD_ADD

                std::vector<std::pair<std::string, std::string>> kvs(lines.size() - 1);
                std::transform(std::begin(lines) + 1, std::end(lines), std::begin(kvs),
                               [](const std::string &line) -> std::pair<std::string, std::string> {
                                   auto ll = Split(line, ":");
                                   if (ll.size() <= 1) {
                                       return {"", ""};
                                   }
                                   auto k = Lower(Trim(ll[0]));
                                   auto v = Trim(ll[1]);
                                   return {k, v};
                               });

                kv.insert(std::begin(kvs), std::end(kvs));
                return RequestHeader(method, std::move(top[1]), std::move(kv));
            }

        public:
            Method method() const noexcept { return _method; }
            const std::string &path() const { return _path; }

            const std::unordered_map<std::string, std::string> &headers() const { return _kv; }

            std::string operator[](const std::string &key) const {
                auto itr = headers().find(Lower(key));
                if (itr == std::end(headers())) {
                    return "";
                }
                return itr->second;
            }
        };
    } // namespace detail

    class Request {
    private:
        detail::RequestHeader _header;
        std::string _body;
        std::unordered_map<std::string, std::string> _pathFragments;

    public:
        Request(detail::RequestHeader header, std::string body,
                std::unordered_map<std::string, std::string> pf)
            : _header(std::move(header))
            , _body(std::move(body))
            , _pathFragments(std::move(pf)) {}

    public:
        Method method() const noexcept { return _header.method(); }
        const std::string &path() const { return _header.path(); }
        const std::unordered_map<std::string, std::string> &headers() const {
            return _header.headers();
        }

        std::string operator[](const std::string &key) const { return _header[key]; }

        const std::string &body() const { return _body; }

        std::string params(const std::string &key) const {
            auto itr = _pathFragments.find(key);
            if (itr == std::end(_pathFragments)) {
                return "";
            }
            return _pathFragments.at(key);
        }
    };

    // response class
    class Response {
    private:
        int _socket;
        std::unordered_map<std::string, std::string> _headers;
        int _status;
        std::string _body;

    public:
        explicit Response(int sock)
            : _socket(sock)
            , _headers({{"connection", "close"},
                        {"content-type", "text/plain"},
                        {"server", "Express.hpp"}})
            , _status(200)
            , _body() {}

    public:
        void sendStatus(int status) {
            _status = status;
            end();
        }

        void header(const std::string &key, const std::string &value) { _headers[key] = value; }

        void end(int status, std::string body) {
            _status = status;
            end(std::move(body));
        }
        void end(std::string body) {
            _body = std::move(body);
            header("content-length", std::to_string(_body.size()));
            end();
        }

        void end() {
            std::stringstream ss;
            ss << "HTTP/1.1 " << _status << " " << detail::statusCode(_status) << REST_HTTP_NEWLINE;
            for (const auto &kv : _headers) {
                ss << kv.first << ": " << kv.second << REST_HTTP_NEWLINE;
            }
            ss << REST_HTTP_NEWLINE;
            ss << _body << REST_HTTP_NEWLINE;

            auto str = ss.str();
            ::write(_socket, str.c_str(), str.size());
        }
    };

    // main class
    class Express {
    public:
        using HandlerType = std::function<void(const Request &, Response &)>;

    private:
        class Handler {
        private:
            Method _method;
            std::regex _path;
            HandlerType _handler;
            std::vector<std::string> _id;

        public:
            Handler() = default;
            Handler(Method method, std::regex path, std::vector<std::string> ids,
                    HandlerType handler)
                : _method(method)
                , _path(std::move(path))
                , _id(std::move(ids))
                , _handler(std::move(handler)) {}
            Handler(const Handler &) = default;
            Handler(Handler &&) = default;

            Handler &operator=(const Handler &) = default;
            Handler &operator=(Handler &&) = default;

        public:
            bool is(Method method, const std::string &path) const {
                return _method == method && std::regex_match(path, _path);
            }

            std::unordered_map<std::string, std::string>
            createPathFragment(const std::string &path) const {
                std::unordered_map<std::string, std::string> fragments;

                std::smatch sm;
                std::regex_match(path, sm, _path);
                for (std::size_t i = 0; i < _id.size(); ++i) {
                    fragments[_id[i]] = sm[i + 1].str();
                }
                return fragments;
            }

            void call(const Request &req, Response &res) const { _handler(req, res); }
        };

    private:
        std::vector<Handler> _handlers;
        std::vector<HandlerType> _beforeRequest;
        bool _isRunning;

    private:
        static std::pair<std::regex, std::vector<std::string>>
        _pathToRegex(const std::string &path) {
            static const std::regex COLON_REGEX(R"(:(\w+))");
            auto first = path.cbegin();
            auto last = path.cend();

            std::vector<std::string> ids;

            std::smatch sm;
            while (std::regex_search(first, last, sm, COLON_REGEX)) {
                ids.emplace_back(sm[1].str());
                first += sm.position(1);
            }

            static const std::regex COLON_REPLACE_REGEX(R"((:\w+))");
            return {std::regex(std::regex_replace(path, COLON_REPLACE_REGEX, R"((\w+))")), ids};
        }

    public:
        Express &use(const HandlerType &handler) {
            std::clog << "set before request handler" << std::endl;
            _beforeRequest.emplace_back(handler);
            return *this;
        }

        Express &use(Method method, const std::string &path, const HandlerType &handler) {
            std::clog << path << std::endl;
            auto pi = _pathToRegex(path);
            Handler h(method, std::move(pi.first), std::move(pi.second), std::move(handler));
            _handlers.emplace_back(std::move(h));
            return *this;
        }

    public:
        Express &get(const std::string &path, const HandlerType &handler) {
            std::clog << "GET ";
            return use(Method::GET, path, handler);
        }

        Express &post(const std::string &path, const HandlerType &handler) {
            std::clog << "POST ";
            return use(Method::POST, path, handler);
        }

        Express &put(const std::string &path, const HandlerType &handler) {
            std::clog << "PUT ";
            return use(Method::PUT, path, handler);
        }

        Express &del(const std::string &path, const HandlerType &handler) {
            std::clog << "DELETE ";
            return use(Method::DEL, path, handler);
        }

    private:
        void doProcess(int sock) const {
            Response res(sock);

            std::string headerStr;
            std::string bodyStr;
            while (true) {
                char buf[1024] = {};
                auto dlen = ::read(sock, &buf, sizeof(buf));
                if (dlen <= 0)
                    continue;

                headerStr.append(buf, dlen);
                auto terminalPos = headerStr.find(REST_HTTP_NEWLINE REST_HTTP_NEWLINE);
                if (terminalPos != std::string::npos) {
                    bodyStr.assign(std::begin(headerStr) + terminalPos + 3, std::end(headerStr));
                    headerStr.erase(terminalPos);
                    break;
                }
            }

            auto reqHeader = detail::RequestHeader::Parse(headerStr);

            switch (reqHeader.method()) {
            case Method::POST:
            case Method::PUT: {
                auto lengthStr = reqHeader["content-length"];
                int length = 0;
                try {
                    length = std::stoi(lengthStr);
                } catch (const std::invalid_argument &e) {
                    std::cout << e.what() << " " << lengthStr << std::endl;
                    res.sendStatus(400); // bad request
                    goto exitFromProcess;
                }

                length -= bodyStr.size();
                while (length > 0) {
                    char buf[1024] = {};
                    auto rl = ::read(sock, &buf, std::min<std::size_t>(sizeof(buf), length));

                    bodyStr.append(buf, rl);
                    length -= rl;
                }
                break;
            }
            default:
                break;
            }

            for (const auto &handler : _handlers) {
                if (handler.is(reqHeader.method(), reqHeader.path())) {
                    auto fragments = handler.createPathFragment(reqHeader.path());
                    handler.call(
                        Request(std::move(reqHeader), std::move(bodyStr), std::move(fragments)),
                        res);
                    goto exitFromProcess;
                }
            }
            res.sendStatus(404);

        exitFromProcess:
            close(sock);
        }

        void doAccept(int acceptSock) const {
            sockaddr_in client = {};
            socklen_t len = sizeof(client);
            auto sock = ::accept(acceptSock, (struct sockaddr *)&client, &len);
            doProcess(sock);
        }

    public:
        void listen(std::uint16_t port = 8080) {
            _isRunning = true;

            auto sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) {
                ::perror("socket");
                std::exit(1);
            }

            int yes;
            if (::setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes)) < 0) {
                ::perror("setsockopt");
                std::exit(2);
            }

            sockaddr_in addr = {};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            addr.sin_addr.s_addr = INADDR_ANY;
            if (::bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
                ::perror("bind");
                std::exit(2);
            }

            if (::listen(sock, 10) < 0) {
                ::perror("listen");
                std::exit(3);
            }

            static constexpr std::size_t MAX_EVENTS = 1024;

            int epfd;
            if ((epfd = epoll_create(MAX_EVENTS)) < 0) {
                ::perror("epoll_create");
                std::exit(4);
            }

            epoll_event event = {};
            event.events = EPOLLIN | EPOLLET;
            event.data.fd = sock;

            if (epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &event) < 0) {
                ::perror("epoll_ctl");
                exit(5);
            }

            std::clog << "Listening on http://0.0.0.0:" << port << std::endl;

            struct epoll_event events[MAX_EVENTS];
            while (_isRunning) {
                auto nfd = epoll_wait(epfd, events, MAX_EVENTS, -1);
                if (nfd < 0) {
                    ::perror("epoll_wait");
                    std::exit(6);
                }

                for (int i = 0; i < nfd; ++i) {
                    if (events[i].data.fd == sock) {
                        doAccept(sock);
                    }
                }
            }

            ::close(sock);
        }

        void stop() { _isRunning = false; }
    };

    namespace detail {
        std::string statusCode(int s) {
#define CODE(code, msg)                                                                            \
    case code:                                                                                     \
        return msg
            switch (s) {
                CODE(100, "Continue");
                CODE(101, "Switching Protocols");
                CODE(102, "Processing");
                CODE(103, "Early Hints");
                CODE(200, "OK");
                CODE(201, "Created");
                CODE(202, "Accepted");
                CODE(203, "Non-Authoritative Information");
                CODE(205, "Reset Content");
                CODE(206, "Partial Content");
                CODE(207, "Multi-Status");
                CODE(208, "Already Reported");
                CODE(226, "IM Used");
                CODE(300, "Multiple Choices");
                CODE(301, "Moved Permanently");
                CODE(302, "Found");
                CODE(303, "See Other");
                CODE(304, "Not Modified");
                CODE(305, "Use Proxy");
                CODE(307, "Temporary Redirect");
                CODE(308, "Permanent Redirect");
                CODE(400, "Bad Request");
                CODE(401, "Unauthorized");
                CODE(402, "Payment Required");
                CODE(403, "Forbidden");
                CODE(404, "Not Found");
                CODE(405, "Method Not Allowed");
                CODE(406, "Not Acceptable");
                CODE(407, "Proxy Authentication Required");
                CODE(408, "Request Timeout");
                CODE(409, "Conflict");
                CODE(410, "Gone");
                CODE(411, "Length Required");
                CODE(412, "Precondition Failed");
                CODE(413, "Payload Too Large");
                CODE(414, "URI Too Long");
                CODE(415, "Unsupported Media Type");
                CODE(416, "Range Not Satisfiable");
                CODE(417, "Expectation Failed");
                CODE(421, "Misdirected Request");
                CODE(422, "Unprocessable Entity");
                CODE(423, "Locked");
                CODE(424, "Failed Dependency");
                CODE(425, "Too Early");
                CODE(426, "Upgrade Required");
                CODE(428, "Precondition Required");
                CODE(429, "Too Many Requests");
                CODE(431, "Request Header Fields Too Large");
                CODE(451, "Unavailable For Legal Reasons");
                CODE(500, "Internal Server Error");
                CODE(501, "Not Implemented");
                CODE(502, "Bad Gateway");
                CODE(503, "Service Unavailable");
                CODE(504, "Gateway Timeout");
                CODE(505, "HTTP Version Not Supported");
                CODE(506, "Variant Also Negotiates");
                CODE(507, "Insufficient Storage");
                CODE(508, "Loop Detected");
                CODE(509, "Bandwidth Limit Exceeded");
                CODE(510, "Not Extended");
                CODE(511, "Network Authentication Required");
            default:
                return "Unknown Status";
            }
#undef CODE
        }
    } // namespace detail
} // namespace express

#undef REST_HTTP_NEWLINE

#endif // CXXREST_EXPRESS_HPP
