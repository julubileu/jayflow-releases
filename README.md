# JayFlow Releases

Este repositório público distribui os binários oficiais do JayFlow. O código-fonte e o processo de desenvolvimento ficam em um repositório privado; aqui permanecem somente o workflow auditável e os artefatos publicados.

## Instalação recomendada por usuário

O alvo inicial deste workflow é `2.0.33-dev`, uma versão de desenvolvimento — não uma versão estável. Baixe o [`JayFlow-setup.exe`](https://github.com/julubileu/jayflow-releases/releases/latest/download/JayFlow-setup.exe) correspondente à release que você pretende testar e execute-o no Windows x64. A página [Releases/latest](https://github.com/julubileu/jayflow-releases/releases/latest) mostra a versão atual, notas, checksums e informações exatas do build.

O setup NSIS instala o JayFlow por usuário, em uma pasta gravável sem elevação administrativa, e mantém um nome estável para automação e documentação. Esse escopo é necessário para que o updater consiga substituir o executável ao lado da aplicação sem depender de privilégios de administrador ou de escrita em `Program Files`. O Windows pode solicitar a instalação ou atualização do Microsoft Edge WebView2, componente usado pela interface do JayFlow.

## Executável portátil (uso avançado)

Cada release também contém `JayFlow-X.Y.Z.exe`. Essa edição portátil é útil para diagnóstico, teste controlado ou ambientes em que um instalador não pode ser usado. Coloque o arquivo em uma pasta gravável pelo usuário e preserve o nome versionado ao arquivá-lo.

O portátil não substitui as conveniências do setup. Se uma política corporativa bloquear o executável, peça a liberação pelo hash publicado em `checksums.txt`; não desative o antivírus ou as proteções do Windows.

## Atualizações assinadas

O JayFlow consulta publicamente `latest.json` e baixa o executável versionado desta página de releases. O manifesto contém a versão, a URL e o SHA-256 do binário; versão e digest são assinados com Ed25519. O aplicativo traz somente a chave pública e só aceita bytes cujo hash e assinatura sejam válidos.

Não há PAT, chave privada ou credencial de GitHub embutida no aplicativo. A atualização pública não depende de túnel, porta adicional ou acesso da VM ao GitHub. A chave privada de release existe somente como secret do workflow; o repositório usa uma deploy key separada e somente leitura para obter o código privado durante o build.

`checksums.txt` permite conferência manual. `buildinfo.txt` registra a versão, o ref solicitado e o SHA exato do código-fonte privado usado no build, sem expor credenciais.

## Requisitos da VM

O JayFlow é instalado apenas no PC Windows. Para usar agentes remotos, cadastre uma VM com:

- Linux x86-64 (`amd64`) acessível por SSH;
- autenticação SSH válida e chave do host verificável;
- subsistema SFTP habilitado na mesma conexão SSH;
- permissão de escrita do usuário em `~/.jayflow` e espaço livre para binário, logs e sessões;
- as CLIs que você pretende usar, como Claude Code ou Codex, instaladas e autenticadas para esse usuário.

O aplicativo leva dentro de si o `jayflowd` Linux da mesma versão e o instala/atualiza em `~/.jayflow/bin` via SFTP. Não é necessário instalar JayFlow na VM, usar `sudo`, abrir uma porta TCP para o daemon ou criar um túnel reverso. Um reboot da VM encerra os processos e sessões que estavam em execução.

## Diagnóstico

Se a instalação ou conexão falhar:

1. Confira a versão e o SHA em `buildinfo.txt` e valide o arquivo com `checksums.txt` na página da release.
2. Abra o Activity Log do JayFlow e preserve a mensagem completa, removendo usuários, endereços e caminhos sensíveis antes de compartilhá-la.
3. Revise host, porta, usuário, autenticação SSH e eventual mudança da chave em `known_hosts`.
4. Confirme que o SFTP funciona e que o usuário consegue criar `~/.jayflow/bin` e `~/.jayflow/logs` sem `sudo`.
5. Na VM, confirme que a CLI escolhida está no `PATH` do usuário e já foi autenticada.

Problemas de integridade, assinatura ou atualização devem ser reportados pelo canal privado descrito em [SECURITY.md](SECURITY.md), e não em uma issue pública.
