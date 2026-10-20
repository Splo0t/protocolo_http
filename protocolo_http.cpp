// ============================================================================
// ARQUIVO DE VALIDAÇÃO DO PROFESSOR: teste_completo_rede_edu.cpp
// Ambiente: Windows 11 (Modo Usuário) + Visual Studio Community 2022
// Padrão exigido: ISO C++23 Standard (/std:c++23preview ou /std:c++latest)
// 
// Nota: Para facilitar o seu teste rápido, o conteúdo do "rede_edu.hpp" já
// está incluído no topo deste arquivo. Basta colar tudo no seu .cpp do VS
// e pressionar F5!
// ============================================================================

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <winhttp.h>

#include <print>
#include <format>
#include <string>
#include <string_view>
#include <expected>
#include <vector>
#include <thread>
#include <chrono>
#include <iostream>

// Vinculação automática no compilador MSVC (dispensa configurar o Linker no VS)
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")

// ============================================================================
// INÍCIO DO CONTEÚDO DE "rede_edu.hpp"
// ============================================================================
namespace rede {

    // Inicializa e finaliza a pilha Winsock2 automaticamente via RAII
    struct InicializadorWinsock {
        InicializadorWinsock() {
            WSADATA d{};
            WSAStartup(MAKEWORD(2, 2), &d);
        }
        ~InicializadorWinsock() {
            WSACleanup();
        }
    };
    inline InicializadorWinsock _auto_init;

    // ------------------------------------------------------------------------
    // FUNÇÃO 1 (Aulas 1 e 2): Cliente TCP Bruto (Texto Puro na Porta 80)
    // ------------------------------------------------------------------------
    inline std::expected<std::string, std::string> enviar_tcp_bruto(
        std::string_view host, std::string_view porta, std::string_view payload)
    {
        addrinfo hints{}, * res = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        std::string host_str(host);
        std::string porta_str(porta);

        if (getaddrinfo(host_str.c_str(), porta_str.c_str(), &hints, &res) != 0) {
            return std::unexpected("Falha na resolucao de DNS (getaddrinfo).");
        }

        SOCKET s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (s == INVALID_SOCKET) {
            freeaddrinfo(res);
            return std::unexpected("Falha ao criar socket no sistema operacional.");
        }

        // Timeout de segurança de 8 segundos para evitar travamento eterno em aula
        DWORD timeout_ms = 8000;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));

        if (connect(s, res->ai_addr, static_cast<int>(res->ai_addrlen)) == SOCKET_ERROR) {
            closesocket(s);
            freeaddrinfo(res);
            return std::unexpected("Falha ao estabelecer conexao TCP com o servidor.");
        }
        freeaddrinfo(res);

        // Envia a requisição montada pelo aluno
        if (send(s, payload.data(), static_cast<int>(payload.size()), 0) == SOCKET_ERROR) {
            closesocket(s);
            return std::unexpected("Erro ao enviar os bytes pela placa de rede.");
        }

        // Recebe os pacotes até o servidor fechar a conexão
        std::string resposta;
        char buffer[4096];
        int lidos = 0;
        while ((lidos = recv(s, buffer, sizeof(buffer), 0)) > 0) {
            resposta.append(buffer, lidos);
        }

        closesocket(s);
        return resposta;
    }

    // ------------------------------------------------------------------------
    // FUNÇÃO 2 (Aula 3): Servidor HTTP Local em Espaço de Usuário (Porta >= 1024)
    // Adicionado parâmetro opcional 'max_requisicoes' (0 = infinito) para facilitar testes
    // ------------------------------------------------------------------------
    template <typename FuncaoTratar>
    inline std::expected<void, std::string> iniciar_servidor_local(
        int porta, FuncaoTratar callback, int max_requisicoes = 0)
    {
        SOCKET srv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (srv == INVALID_SOCKET) {
            return std::unexpected("Erro ao criar socket do servidor.");
        }

        // Permite reusar a porta imediatamente caso o aluno feche e abra o programa rápido
        int opt = 1;
        setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));

        sockaddr_in end{};
        end.sin_family = AF_INET;
        end.sin_addr.s_addr = INADDR_ANY;
        end.sin_port = htons(static_cast<u_short>(porta));

        if (bind(srv, reinterpret_cast<sockaddr*>(&end), sizeof(end)) == SOCKET_ERROR) {
            closesocket(srv);
            return std::unexpected("Porta em uso ou bloqueada pelo firewall local.");
        }

        if (listen(srv, SOMAXCONN) == SOCKET_ERROR) {
            closesocket(srv);
            return std::unexpected("Erro ao colocar o socket em modo de escuta (listen).");
        }

        int atendidas = 0;
        while (max_requisicoes == 0 || atendidas < max_requisicoes) {
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
            atendidas++;
        }

        closesocket(srv);
        return {};
    }

    // ------------------------------------------------------------------------
    // FUNÇÃO 3 (Aula 4): Cliente HTTPS Nativo com Inspeção de Certificado X.509
    // ------------------------------------------------------------------------
    struct RespostaHttps {
        int codigo_status{};
        std::string cabecalhos_resposta;
        std::string corpo;
        std::string titular_certificado;
        std::string emissor_certificado;
    };

    inline std::expected<RespostaHttps, std::string> requisitar_https_nativo(
        std::wstring_view dominio, std::wstring_view caminho)
    {
        // Usa proxy automático do Windows 11 caso a rede da universidade exija
        HINTERNET hSession = WinHttpOpen(L"CursoEngSoft-CPP23/1.0",
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return std::unexpected("Erro ao abrir sessao WinHTTP.");

        std::wstring dom_str(dominio);
        std::wstring cam_str(caminho);

        HINTERNET hConnect = WinHttpConnect(hSession, dom_str.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            return std::unexpected("Erro ao preparar conexao HTTPS.");
        }

        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", cam_str.c_str(),
            nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return std::unexpected("Erro ao criar estrutura de requisicao TLS.");
        }

        // Executa o Handshake TLS (ClientHello / ServerHello / Validação de Certificado) e envia o GET
        if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
            !WinHttpReceiveResponse(hRequest, nullptr)) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return std::unexpected("Falha no Handshake TLS ou Certificado Digital invalido.");
        }

        RespostaHttps resultado{};

        // 1. Extrai o código de status HTTP (ex: 200, 301, 404)
        DWORD status = 0, tam_status = sizeof(status);
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &status, &tam_status, WINHTTP_NO_HEADER_INDEX);
        resultado.codigo_status = static_cast<int>(status);

        // 2. Extrai os cabeçalhos brutos devolvidos pelo servidor
        DWORD tam_cab = 0;
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX, nullptr, &tam_cab, WINHTTP_NO_HEADER_INDEX);
        if (tam_cab > 0) {
            std::wstring wcab(tam_cab / sizeof(wchar_t), L'\0');
            if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX, wcab.data(), &tam_cab, WINHTTP_NO_HEADER_INDEX)) {
                for (wchar_t c : wcab) {
                    if (c != L'\0') resultado.cabecalhos_resposta += static_cast<char>(c);
                }
            }
        }

        // 3. Extrai os metadados do Certificado Digital X.509 negociado no canal TLS
        WINHTTP_CERTIFICATE_INFO cert{};
        DWORD tam_cert = sizeof(cert);
        if (WinHttpQueryOption(hRequest, WINHTTP_OPTION_SECURITY_CERTIFICATE_STRUCT, &cert, &tam_cert)) {
            if (cert.lpszSubjectInfo) {
                std::wstring wsub(cert.lpszSubjectInfo);
                for (wchar_t c : wsub) resultado.titular_certificado += (c < 128 && c >= 32) ? static_cast<char>(c) : ' ';
                LocalFree(cert.lpszSubjectInfo);
            }
            if (cert.lpszIssuerInfo) {
                std::wstring wiss(cert.lpszIssuerInfo);
                for (wchar_t c : wiss) resultado.emissor_certificado += (c < 128 && c >= 32) ? static_cast<char>(c) : ' ';
                LocalFree(cert.lpszIssuerInfo);
            }
        }

        // 4. Lê o payload (corpo HTML/JSON) já desencriptado pela camada TLS
        DWORD disponivel = 0;
        while (WinHttpQueryDataAvailable(hRequest, &disponivel) && disponivel > 0) {
            std::vector<char> buf(disponivel);
            DWORD lidos = 0;
            if (WinHttpReadData(hRequest, buf.data(), disponivel, &lidos)) {
                resultado.corpo.append(buf.data(), lidos);
            }
        }

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return resultado;
    }
}
// ============================================================================
// FIM DO CONTEÚDO DE "rede_edu.hpp"
// ============================================================================


// ============================================================================
// SUÍTE DE TESTES DAS 4 AULAS PARA O PROFESSOR
// ============================================================================

// --- TESTE 1: Simula a Aula 1 (Cliente HTTP Bruto via Socket TCP) ---
bool testar_aula_1_cliente_tcp() {
    std::println("\n------------------------------------------------------------");
    std::println("[TESTE 1 - AULA 1] Testando rede::enviar_tcp_bruto (Porta 80)");
    std::println("------------------------------------------------------------");

    std::string host = "example.com";
    std::string req = std::format(
        "GET / HTTP/1.1\r\n"
        "Host: {}\r\n"
        "User-Agent: TesteProfessorCPP23/1.0\r\n"
        "Connection: close\r\n"
        "\r\n",
        host
    );

    auto res = rede::enviar_tcp_bruto(host, "80", req);
    if (!res.has_value()) {
        std::println(" -> [FALHOU] Erro de rede: {}", res.error());
        return false;
    }

    std::string_view texto = res.value();
    bool contem_200 = texto.starts_with("HTTP/1.1 200 OK");
    bool contem_separador = texto.contains("\r\n\r\n");

    std::println(" -> Bytes recebidos: {} bytes", texto.size());
    std::println(" -> Primeira linha valida (HTTP/1.1 200 OK)? {}", contem_200 ? "SIM" : "NAO");
    std::println(" -> Delimitador CRLF duplo (\\r\\n\\r\\n) encontrado? {}", contem_separador ? "SIM" : "NAO");

    return contem_200 && contem_separador;
}

// --- TESTE 2: Simula a Aula 2 (Parser de Structs sobre a resposta TCP) ---
bool testar_aula_2_parser_http() {
    std::println("\n------------------------------------------------------------");
    std::println("[TESTE 2 - AULA 2] Testando Parsing de Status Code e Corpo");
    std::println("------------------------------------------------------------");

    // Pede uma página que não existe para testar se o parser captura o 404 ou 200
    std::string req =
        "GET /pagina_inexistente_teste_123.html HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Connection: close\r\n\r\n";

    auto res = rede::enviar_tcp_bruto("example.com", "80", req);
    if (!res) {
        std::println(" -> [FALHOU] {}", res.error());
        return false;
    }

    std::string_view bruta = res.value();
    size_t pos_divisao = bruta.find("\r\n\r\n");
    if (pos_divisao == std::string_view::npos) return false;

    std::string_view cabecalhos = bruta.substr(0, pos_divisao);
    std::string_view corpo = bruta.substr(pos_divisao + 4);

    // Extrai o código numérico após "HTTP/1.1 "
    int status_extraido = 0;
    size_t espaco = cabecalhos.find(' ');
    if (espaco != std::string_view::npos) {
        std::string cod_str(cabecalhos.substr(espaco + 1, 3));
        status_extraido = std::stoi(cod_str);
    }

    std::println(" -> Codigo de Status extraido na struct: {}", status_extraido);
    std::println(" -> Tamanho isolado dos cabecalhos: {} bytes", cabecalhos.size());
    std::println(" -> Tamanho isolado do corpo HTML: {} bytes", corpo.size());

    return (status_extraido == 404 || status_extraido == 200) && !corpo.empty();
}

// --- TESTE 3: Simula a Aula 3 (Servidor Local em Porta Alta + Autoteste) ---
bool testar_aula_3_servidor_local() {
    std::println("\n------------------------------------------------------------");
    std::println("[TESTE 3 - AULA 3] Testando rede::iniciar_servidor_local (8080)");
    std::println("------------------------------------------------------------");

    int porta_teste = 8080;

    // 1. Dispara uma thread em background que atuará como "o navegador do aluno"
    // após 300 milissegundos, enviando uma requisição para localhost:8080
    std::string resposta_recebida_pelo_cliente;
    std::jthread thread_cliente([&]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        std::string req_local =
            "GET /ola-professor HTTP/1.1\r\n"
            "Host: localhost:8080\r\n"
            "Connection: close\r\n\r\n";

        auto r = rede::enviar_tcp_bruto("127.0.0.1", std::to_string(porta_teste), req_local);
        if (r.has_value()) {
            resposta_recebida_pelo_cliente = r.value();
        }
        });

    // 2. Roda o servidor na thread principal para atender 1 requisição (max_requisicoes = 1)
    std::println(" -> Subindo servidor local na porta {} (Modo Usuario)...", porta_teste);
    auto status_srv = rede::iniciar_servidor_local(porta_teste, [](std::string_view req_navegador) -> std::string {
        // Verifica se a requisição de teste chegou corretamente
        if (req_navegador.starts_with("GET /ola-professor")) {
            std::string html = "<html><body><h1>Servidor C++23 Funcionando!</h1></body></html>";
            return std::format(
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html; charset=utf-8\r\n"
                "Content-Length: {}\r\n"
                "Connection: close\r\n"
                "\r\n"
                "{}", html.size(), html
            );
        }
        return "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        }, 1); // Atende 1 cliente e encerra o loop para continuar o teste

    if (!status_srv.has_value()) {
        std::println(" -> [FALHOU] Erro no servidor: {}", status_srv.error());
        return false;
    }

    thread_cliente.join();

    bool sucesso = resposta_recebida_pelo_cliente.contains("Servidor C++23 Funcionando!");
    std::println(" -> Servidor respondeu em localhost:8080 com sucesso? {}", sucesso ? "SIM" : "NAO");
    return sucesso;
}

// --- TESTE 4: Simula a Aula 4 (HTTPS Nativo e Certificado X.509) ---
bool testar_aula_4_https_nativo() {
    std::println("\n------------------------------------------------------------");
    std::println("[TESTE 4 - AULA 4] Testando rede::requisitar_https_nativo (443)");
    std::println("------------------------------------------------------------");

    auto res = rede::requisitar_https_nativo(L"example.com", L"/");
    if (!res.has_value()) {
        std::println(" -> [FALHOU] Erro TLS/HTTPS: {}", res.error());
        return false;
    }

    const auto& dados = res.value();
    std::println(" -> Handshake TLS concluido com sucesso!");
    std::println(" -> Status HTTP Seguro: {}", dados.codigo_status);
    std::println(" -> Titular do Certificado X.509: {}", dados.titular_certificado);
    std::println(" -> Emissor do Certificado (CA):  {}", dados.emissor_certificado);
    std::println(" -> Tamanho do HTML desencriptado: {} bytes", dados.corpo.size());

    return dados.codigo_status == 200 && !dados.corpo.empty();
}

int main() {
    // Configura o console do Windows 11 para exibir acentos UTF-8 corretamente
    SetConsoleOutputCP(CP_UTF8);

    std::println("============================================================");
    std::println("   VALIDADOR DO CABECALHO DIDATICO (rede_edu.hpp) - C++23   ");
    std::println("============================================================");

    bool ok1 = testar_aula_1_cliente_tcp();
    bool ok2 = testar_aula_2_parser_http();
    bool ok3 = testar_aula_3_servidor_local();
    bool ok4 = testar_aula_4_https_nativo();

    std::println("\n============================================================");
    std::println("                  RESUMO DO DIAGNOSTICO                     ");
    std::println("============================================================");
    std::println(" [{}] Aula 1: Cliente TCP Bruto (Porta 80)", ok1 ? "OK" : "ERRO");
    std::println(" [{}] Aula 2: Extracao e Parsing de Resposta", ok2 ? "OK" : "ERRO");
    std::println(" [{}] Aula 3: Servidor HTTP Local (Porta 8080)", ok3 ? "OK" : "ERRO");
    std::println(" [{}] Aula 4: Cliente HTTPS + Certificado X.509", ok4 ? "OK" : "ERRO");
    std::println("============================================================");

    if (ok1 && ok2 && ok3 && ok4) {
        std::println("\n>>> TUDO PRONTO! O ambiente da universidade suporta todas as 4 aulas!");
    }
    else {
        std::println("\n>>> ATENCAO: Algum teste falhou. Verifique se ha bloqueio de rede/proxy.");
    }

    // Opção extra caso você queira testar o servidor da Aula 3 no navegador real
    std::print("\nDeseja deixar o servidor da Aula 3 aberto para testar no navegador Edge/Chrome? (s/n): ");
    char opcao = 'n';
    std::cin >> opcao;

    if (opcao == 's' || opcao == 'S') {
        std::println("\n[SERVIDOR ATIVO] Abra o navegador em: http://localhost:8080/teste");
        std::println("(O servidor encerrara automaticamente apos voce atualizar a pagina 3 vezes)\n");

        int contador = 0;
        rede::iniciar_servidor_local(8080, [&](std::string_view req) -> std::string {
            contador++;
            std::println(" -> Requisicao #{} recebida do navegador!", contador);

            std::string pagina = std::format(
                "<html><head><meta charset='utf-8'><title>Aula 3 C++23</title></head>"
                "<body style='font-family: sans-serif; padding: 30px;'>"
                "<h1>Servidor Didático C++23 Funcionando!</h1>"
                "<p>Esta resposta foi gerada pelo seu código no Visual Studio (Acesso #{}/3).</p>"
                "<h3>Cabeçalhos que o seu navegador enviou:</h3>"
                "<pre style='background: #f0f0f0; padding: 15px; border-radius: 5px;'>{}</pre>"
                "</body></html>",
                contador, req
            );

            return std::format(
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html; charset=utf-8\r\n"
                "Content-Length: {}\r\n"
                "Connection: close\r\n"
                "\r\n"
                "{}", pagina.size(), pagina
            );
            }, 3);

        std::println("\n[SERVIDOR ENCERRADO] 3 requisicoes atendidas com sucesso!");
    }

    return 0;
}