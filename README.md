# Protocolo HTTP em C++23

Projeto didático da disciplina de **Redes de Computadores** para demonstrar, na prática, como o
protocolo HTTP funciona por dentro. O código usa apenas a API nativa do Windows
(Winsock2 e WinHTTP), sem bibliotecas HTTP de terceiros, deixando visíveis os bytes que
trafegam na rede.

## O que o projeto faz

O executável roda uma suíte de validação dividida em quatro etapas, uma para cada aula:

| Etapa | Recurso demonstrado | Implementação |
|-------|---------------------|---------------|
| 1 | Cliente HTTP bruto via socket TCP na porta 80 | `rede::enviar_tcp_bruto` |
| 2 | Parsing manual de status code, cabeçalhos e corpo | `testar_aula_2_parser_http` |
| 3 | Servidor HTTP local em porta alta (8080) | `rede::iniciar_servidor_local` |
| 4 | Cliente HTTPS com handshake TLS e inspeção do certificado X.509 | `rede::requisitar_https_nativo` |

Além da suíte automática, o programa oferece a opção de manter o servidor da Aula 3 aberto
para ser acessado pelo navegador em `http://localhost:8080/teste`.

## Estrutura do repositório

```
protocolo_http.slnx          Solução do Visual Studio
protocolo_http.vcxproj       Configuração do projeto (C++23, x64)
protocolo_http.cpp           Suíte de testes das quatro aulas
rede_edu.hpp                 Cabeçalho com as funções de rede
```

> O arquivo `protocolo_http.cpp` contém uma cópia do conteúdo de `rede_edu.hpp` no topo, para
> permitir colar o código diretamente no Visual Studio e executar com F5. O cabeçalho
> permanece no repositório como referência modular.

## Requisitos

- Windows 10/11
- Visual Studio 2022 (Community ou superior) com a carga de trabalho **Desenvolvimento para desktop com C++**
- SDK do Windows 10 ou 11
- Toolset MSVC compatível com C++23 (`/std:c++23preview` ou `/std:c++latest`)

## Como compilar e executar

1. Abra `protocolo_http.slnx` no Visual Studio.
2. Selecione a configuração **Debug | x64** (é a que está definida para C++23).
3. Pressione `F5` (ou `Ctrl+F5`).

As bibliotecas `ws2_32.lib` e `winhttp.lib` são vinculadas automaticamente por
`#pragma comment(lib, ...)`, então não é necessário configurar o linker manualmente.

Pela linha de comando, com o MSVC já configurado:

```powershell
cl /std:c++latest /EHsc /W3 /Fe:protocolo_http.exe protocolo_http.cpp
```

## Observações

- Os testes 1, 2 e 4 acessam a internet (`example.com`), portanto dependem de rede liberada e,
  em redes com proxy, do proxy configurado no Windows.
- O teste 3 usa a porta `8080`; se ela estiver ocupada, o firewall ou outro processo impedirão
  a execução.
- O arquivo `protocolo_http.cpp` usa `std::print`/`std::println` e `std::expected`, recursos do
  C++23.

## Licença

Este projeto é disponibilizado para fins educacionais. Não há licença declarada; entre em
contato com o autor para reutilização.
