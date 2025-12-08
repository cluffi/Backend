#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <sqlite3.h>

#include <iostream>
#include <string>
#include <vector>

#include <openssl/ssl.h>
#include <openssl/err.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "sqlite3.lib")

using namespace std;

static void init_winsock()
{
    WSADATA wsaData;
    int rv = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (rv != 0)
    {
         cerr << "WSAStartup failed: " << rv << "\n";
        exit(1);
    }
}

static void cleanup_winsock()
{
    WSACleanup();
}

static SSL_CTX* create_ssl_ctx(const char* cert_file, const char* key_file)
{
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        cerr << "SSL_CTX_new failed\n";
        return nullptr;
    }

    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0)
    {
        std::cerr << "SSL_CTX_use_certificate_file failed\n";
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return nullptr;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0)
    {
        std::cerr << "SSL_CTX_use_PrivateKey_file failed\n";
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return nullptr;
    }

    if (!SSL_CTX_check_private_key(ctx))
    {
        std::cerr << "Private key does not match the certificate public key\n";
        SSL_CTX_free(ctx);
        return nullptr;
    }

    return ctx;
}

string read_http_path_from_ssl(SSL* ssl)
{
    char buf[4096];
    std::string accum;

    while (true)
    {
        int r = SSL_read(ssl, buf, sizeof(buf));
        if (r <= 0)
        {
            int err = SSL_get_error(ssl, r);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
            {
                continue;
            }
        }

        accum.append(buf, buf + r);
        if (accum.find("\r\n\r\n") != string::npos)
        {
            break;
        }
        
        if (accum.size() > 64 * 1024)
        {
            std::cerr << "Headers too large\n";
            return "";
        }
    }

    return accum;
}

string get_achievement(const string& game_name, const string& achievement_name)
{
    sqlite3* db = nullptr;

    if (sqlite3_open("Achievements.db", &db) != SQLITE_OK)
    {
        std::cerr << "SQLite open error: "
            << sqlite3_errmsg(db) << "\n";
        return "";
    }

    const char* sql =
        "SELECT AchievementText "
        "FROM Games "
        "WHERE Game = ? AND AchievementName = ? "
        "LIMIT 1";

    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);

    sqlite3_bind_text(stmt, 1, game_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, achievement_name.c_str(), -1, SQLITE_TRANSIENT);

    string result;

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* txt = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));

        if (txt)
            result = std::string(txt);
    }

    sqlite3_finalize(stmt);
    return result;
}

void parse_query(string& source_string, vector<string>& keys, vector<string>& values)
{
    size_t pos = 0;

    keys.clear();
    values.clear();

    while (pos < source_string.size())
    {
        size_t amp = source_string.find('&', pos);
        if (amp == std::string::npos)
            amp = source_string.size();

        size_t eq = source_string.find('=', pos);
        if (eq != std::string::npos && eq < amp)
        {
            keys.push_back(source_string.substr(pos, eq - pos));
            values.push_back(source_string.substr(eq + 1, amp - eq - 1));
        }

        pos = amp + 1;
    }
}

int main()
{
    const char* cert_file = "server.crt";
    const char* key_file = "server.key";

    init_winsock();

    SSL_CTX* ctx = create_ssl_ctx(cert_file, key_file);
    if (!ctx)
    {
        cleanup_winsock();
        return 1;
    }

    SOCKET listenSock = INVALID_SOCKET;
    addrinfo hints{}, * res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    int rv = getaddrinfo("localhost", "8443", &hints, &res);
    if (rv != 0)
    {
        std::cerr << "getaddrinfo failed: " << rv << "\n";
        SSL_CTX_free(ctx);
        cleanup_winsock();
        return 1;
    }

    listenSock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (listenSock == INVALID_SOCKET)
    {
        std::cerr << "socket failed: " << WSAGetLastError() << "\n";
        freeaddrinfo(res);
        SSL_CTX_free(ctx);
        cleanup_winsock();
        return 1;
    }

    BOOL yes = TRUE;
    setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes));

    if (bind(listenSock, res->ai_addr, (int)res->ai_addrlen) == SOCKET_ERROR)
    {
        std::cerr << "bind failed: " << WSAGetLastError() << "\n";
        closesocket(listenSock);
        freeaddrinfo(res);
        SSL_CTX_free(ctx);
        cleanup_winsock();
        return 1;
    }

    freeaddrinfo(res);

    if (listen(listenSock, SOMAXCONN) == SOCKET_ERROR)
    {
        std::cerr << "listen failed: " << WSAGetLastError() << "\n";
        closesocket(listenSock);
        SSL_CTX_free(ctx);
        cleanup_winsock();
        return 1;
    }

    std::cout << "Listening on localhost:8443\n";

    while (true)
    {
        SOCKET clientSock = accept(listenSock, nullptr, nullptr);
        if (clientSock == INVALID_SOCKET)
        {
            std::cerr << "accept failed: " << WSAGetLastError() << "\n";
            break;
        }

        std::cout << "Client connected\n";

        SSL* ssl = SSL_new(ctx);
        if (!ssl)
        {
            std::cerr << "SSL_new failed\n";
            closesocket(clientSock);
            continue;
        }

        BIO* sbio = BIO_new_socket((int)clientSock, BIO_NOCLOSE);
        SSL_set_bio(ssl, sbio, sbio);

        if (SSL_accept(ssl) <= 0)
        {
            std::cerr << "SSL_accept failed\n";
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            closesocket(clientSock);
            continue;
        }

        string http = read_http_path_from_ssl(ssl);
        std::string first_line = http.substr(0, http.find("\r\n"));

        size_t sp1 = first_line.find(' ');
        size_t sp2 = first_line.find(' ', sp1 + 1);
        std::string url = first_line.substr(sp1 + 1, sp2 - sp1 - 1);
        size_t q = url.find('?');
        string query = (q == std::string::npos) ? "" : url.substr(q + 1);

        vector<string> keys;
        vector<string> values;

        parse_query(query, keys, values);

        string body;

        if (values.size() > 1)
            body = get_achievement(values[0], values[1]);
        else
            body = "";

        string resp =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            "Content-Length: " + to_string(body.size()) + "\r\n"
            "Connection: close\r\n"
            "\r\n" + body;

        SSL_write(ssl, resp.data(), resp.size());
        SSL_shutdown(ssl);
        SSL_free(ssl);
        closesocket(clientSock);

        std::cout << "Client handled\n";
    }

    closesocket(listenSock);
    SSL_CTX_free(ctx);
    cleanup_winsock();
    return 0;
}
