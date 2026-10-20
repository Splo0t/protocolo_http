// rede_edu.hpp - Infraestrutura de Rede para Visual Studio (Windows 11)
#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <winhttp.h>

#include <string>
#include <string_view>
#include <expected>
#include <vector>

// Vincula as bibliotecas nativas do Windows automaticamente no MSVC
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")

namespace rede {

    // Inicializa e finaliza a pilha TCP/IP do Windows nos bastidores
    struct InicializadorWinsock {
        InicializadorWinsock() { WSADATA d; WSAStartup(MAKEWORD(2, 2), &d); }
        ~InicializadorWinsock() { WSACleanup(); }
    };
    inline InicializadorWinsock _auto_init;

    // AULA 1 e 2: Envia texto puro via socket TCP (Porta 80) e retorna a resposta bruta
    inline std::expected<std::string, std::string> enviar_tcp_bruto(
        std::string_view host, std::string_view porta, std::string_view payload)
    {
        addrinfo hints{}, * res = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        std::string host_str(host);
        std::string porta_str(porta);

        if (getaddrinfo(host_str.c_str(), porta_str.c_str(), &hints, &res) != 0)
            return std::unexpected("Falha na resolucao de DNS.");

        SOCKET s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (s == INVALID_SOCKET) {
            freeaddrinfo(res);
            return std::unexpected("Falha ao criar socket no sistema operacional.");
        }

        if (connect(s, res->ai_addr, static_cast<int>(res->ai_addrlen)) == SOCKET_ERROR) {
            closesocket(s);
            freeaddrinfo(res);
            return std::unexpected("Falha ao estabelecer conexao TCP com o servidor.");
        }
        freeaddrinfo(res);

        send(s, payload.data(), static_cast<int>(payload.size()), 0);

        std::string resposta;
        char buffer[4096];
        int lidos = 0;
        while ((lidos = recv(s, buffer, sizeof(buffer), 0)) > 0) {
            resposta.append(buffer, lidos);
        }

        closesocket(s);
        return resposta;
    }

    // AULA 3: Servidor TCP local em porta alta (Ex: 8080)
    template <typename FuncaoTratar>
    inline std::expected<void, std::string> iniciar_servidor_local(int porta, FuncaoTratar callback) {
        SOCKET srv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (srv == INVALID_SOCKET) return std::unexpected("Erro ao criar socket do servidor.");

        sockaddr_in end{};
        end.sin_family = AF_INET;
        end.sin_addr.s_addr = INADDR_ANY;
        end.sin_port = htons(static_cast<u_short>(porta));

        if (bind(srv, reinterpret_cast<sockaddr*>(&end), sizeof(end)) == SOCKET_ERROR) {
            closesocket(srv);
            return std::unexpected("Porta em uso ou bloqueada pelo firewall local.");
        }

        listen(srv, SOMAXCONN);

        while (true) {
            SOCKET cli = accept(srv, nullptr, nullptr);
            if (cli == INVALID_SOCKET) continue;

            char buffer[8192]{};
            int lidos = recv(cli, buffer, sizeof(buffer) - 1, 0);
            if (lidos > 0) {
                std::string req(buffer, lidos);
                std::string resp = callback(req);
                send(cli, resp.data(), static_cast<int>(resp.size()), 0);
            }
            closesocket(cli);
        }
        return {};
    }

    // AULA 4: Estrutura com dados extraídos de uma conexão HTTPS real
    struct RespostaHttps {
        int codigo_status{};
        std::string cabecalhos_resposta;
        std::string corpo;
        std::string info_certificado;
    };

    // AULA 4: Executa requisição HTTPS usando a camada TLS nativa do Windows 11
    inline std::expected<RespostaHttps, std::string> requisitar_https_nativo(
        std::wstring_view dominio, std::wstring_view caminho)
    {
        HINTERNET hSession = WinHttpOpen(L"CursoEngSoft-CPP23/1.0",
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return std::unexpected("Erro ao abrir sessao WinHTTP.");

        HINTERNET hConnect = WinHttpConnect(hSession, dominio.data(), INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!hConnect) { WinHttpCloseHandle(hSession); return std::unexpected("Erro ao preparar conexao HTTPS."); }

        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", caminho.data(),
            nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return std::unexpected("Erro ao criar requisicao TLS."); }

        if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
            !WinHttpReceiveResponse(hRequest, nullptr)) {
            WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
            return std::unexpected("Falha no Handshake TLS ou na verificacao do Certificado Digital.");
        }

        RespostaHttps resultado{};

        // 1. Extrai código de status
        DWORD status = 0, tam_status = sizeof(status);
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &status, &tam_status, WINHTTP_NO_HEADER_INDEX);
        resultado.codigo_status = static_cast<int>(status);

        // 2. Extrai cabeçalhos brutos devolvidos pelo servidor
        DWORD tam_cab = 0;
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX, nullptr, &tam_cab, WINHTTP_NO_HEADER_INDEX);
        if (tam_cab > 0) {
            std::wstring wcab(tam_cab / sizeof(wchar_t), L'\0');
            WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX, wcab.data(), &tam_cab, WINHTTP_NO_HEADER_INDEX);
            for (wchar_t c : wcab) if (c != L'\0') resultado.cabecalhos_resposta += static_cast<char>(c);
        }

        // 3. Extrai informações do Certificado X.509 negociado no TLS
        WINHTTP_CERTIFICATE_INFO cert{};
        DWORD tam_cert = sizeof(cert);
        if (WinHttpQueryOption(hRequest, WINHTTP_OPTION_SECURITY_CERTIFICATE_STRUCT, &cert, &tam_cert)) {
            if (cert.lpszSubjectInfo) {
                std::wstring wsub(cert.lpszSubjectInfo);
                for (wchar_t c : wsub) resultado.info_certificado += static_cast<char>(c);
                LocalFree(cert.lpszSubjectInfo);
            }
            if (cert.lpszIssuerInfo) LocalFree(cert.lpszIssuerInfo);
        }

        // 4. Lê o corpo da resposta desencriptado
        DWORD disponivel = 0;
        while (WinHttpQueryDataAvailable(hRequest, &disponivel) && disponivel > 0) {
            std::vector<char> buf(disponivel);
            DWORD lidos = 0;
            WinHttpReadData(hRequest, buf.data(), disponivel, &lidos);
            resultado.corpo.append(buf.data(), lidos);
        }

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return resultado;
    }
}