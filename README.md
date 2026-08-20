# JayFlow Releases

Este repositório público distribui os binários oficiais do JayFlow. O código-fonte e o processo de desenvolvimento ficam em um repositório privado; aqui permanecem somente o workflow auditável e os artefatos publicados.

## Instalação recomendada por usuário

O alvo inicial deste workflow é `2.0.33-dev`, uma versão de desenvolvimento — não uma versão estável. Baixe o [`JayFlow-setup.exe`](https://github.com/julubileu/jayflow-releases/releases/latest/download/JayFlow-setup.exe) correspondente à release que você pretende testar e execute-o no Windows x64. A página [Releases/latest](https://github.com/julubileu/jayflow-releases/releases/latest) mostra a versão atual, notas, checksums e informações exatas do build.

O setup NSIS instala o JayFlow por usuário, em uma pasta gravável sem elevação administrativa, e mantém um nome estável para automação e documentação. Esse escopo é necessário para que o updater consiga substituir o executável ao lado da aplicação sem depender de privilégios de administrador ou de escrita em `Program Files`. O Windows pode solicitar a instalação ou atualização do Microsoft Edge WebView2, componente usado pela interface do JayFlow.

O destino padrão do setup é `%LOCALAPPDATA%\Programs\JayFlow`. O pipeline audita o gerador NSIS pinado, o PE produzido, o recurso de versão e o overlay estrutural do instalador. O overlay deve começar exatamente no fim das seções PE e conter o `firstheader` canônico do NSIS (`0xDEADBEEF` e `NullsoftInst`) com limites coerentes; renomear o portátil como setup não satisfaz essa prova. O `AppVersion` do aplicativo preserva a versão completa, inclusive o sufixo `-dev`; já o recurso numérico exigido pelo Windows tem quatro componentes `X.Y.Z.0`. Cada componente `X`, `Y` e `Z` é limitado a `0..65535`, e o formato numérico do Windows não comporta o sufixo `-dev`.

Os executáveis ainda **não têm assinatura Authenticode**. Authenticode exige um certificado de code signing separado da chave Ed25519 usada pelo updater. Portanto, o Windows/SmartScreen ainda pode exibir um aviso do Windows mesmo quando os hashes e as assinaturas Ed25519 abaixo forem válidos; este repositório não apresenta checksum Ed25519 como se fosse Authenticode.

## Executável portátil (uso avançado)

Cada release também contém `JayFlow-X.Y.Z.exe`. Essa edição portátil é útil para diagnóstico, teste controlado ou ambientes em que um instalador não pode ser usado. Coloque o arquivo em uma pasta gravável pelo usuário e preserve o nome versionado ao arquivá-lo.

O portátil não substitui as conveniências do setup. Se uma política corporativa bloquear o executável, peça a liberação pelo hash publicado em `checksums.txt`; não desative o antivírus ou as proteções do Windows.

## Atualizações assinadas

O JayFlow consulta publicamente `latest.json` e baixa o executável versionado desta página de releases. O manifesto contém a versão, a URL e o SHA-256 do binário; versão e digest são assinados com Ed25519. O aplicativo traz somente a chave pública e só aceita bytes cujo hash e assinatura sejam válidos.

Não há PAT, chave privada ou credencial de GitHub embutida no aplicativo. A atualização pública não depende de túnel, porta adicional ou acesso da VM ao GitHub. A chave privada de release existe somente como secret do workflow; o repositório usa uma deploy key separada e somente leitura para obter o código privado durante o build.

Cada release tem oito assets e nenhum nome adicional:

- `JayFlow-X.Y.Z.exe`, portátil;
- `JayFlow-X.Y.Z-setup.exe` e `JayFlow-setup.exe`, dois nomes para os mesmos bytes finais do setup;
- `buildinfo.txt`, com tag, commit, versão Windows e escopo do instalador;
- `latest.json`, manifesto do updater com assinatura Ed25519 sobre `jayflow-update-v1\n<version>\n<sha256>\n`;
- `release-manifest.json` e sua assinatura destacada `release-manifest.sig`, que autenticam nome, tamanho e SHA-256 do portátil, dos dois nomes do setup e do buildinfo;
- `checksums.txt`, que registra os SHA-256 desses quatro arquivos e dos três metadados assinados. Ele não contém um auto-hash impossível.

O build e a assinatura rodam em jobs/runners separados. O primeiro recebe somente a deploy key read-only do fonte privado e envia os quatro assets unsigned por um artifact interno. O ELF `jayflowd` já auditado viaja em outro artifact interno, fora de `dist`, e nunca é publicado. O segundo faz checkout somente deste repositório público, compila o auditor antes de receber a chave Ed25519, baixa os dois artifacts e confirma estaticamente que o PE contém todos os bytes do mesmo ELF. O ELF não é executado nesse job. Só depois dessa auditoria o secret é disponibilizado aos passos mínimos de derivação e assinatura.

A tag, o commit e os binários também são ligados entre si. `buildinfo.txt` deve conter exatamente a ref e o SHA validados, e o `vcs.revision` gravado pelo Go no portátil deve ser o mesmo SHA. O pipeline deriva `SOURCE_DATE_EPOCH` do timestamp desse commit, constrói aplicativo e setup NSIS duas vezes a partir das mesmas entradas, remove os outputs entre as execuções e exige igualdade byte a byte. Apenas o segundo build é encaminhado para assinatura.

## Verificação manual

Baixe os oito assets da mesma release para um diretório sem arquivos extras. Obtenha a chave pública Ed25519 por um canal independente e confiável — por exemplo, do build JayFlow já confiável que a incorpora — e não do conjunto de arquivos que está sendo verificado. A partir de um checkout confiável deste repositório, compile e execute o verificador padrão:

```bash
go build -trimpath -o ./jayflow-release-tool ./cmd/release-tool
./jayflow-release-tool verify-bundle \
  -version 2.0.33-dev \
  -dir /caminho/para/os/assets \
  -portable-url https://github.com/julubileu/jayflow-releases/releases/download/v2.0.33-dev/JayFlow-2.0.33-dev.exe \
  -public-key "$JAYFLOW_RELEASE_PUBLIC_KEY"
```

`verify-bundle` rejeita arquivo ausente ou extra, valida as duas assinaturas Ed25519, recalcula todos os hashes e tamanhos autenticados, confere `checksums.txt`, exige que os dois setups sejam idênticos e compara o `latest.json` aos bytes do portátil. Como conferência adicional sem autenticação de origem, `sha256sum -c checksums.txt` também pode ser usado dentro do diretório.

A publicação ocorre como draft: primeiro os binários e metadados, depois `latest.json` isoladamente e por último a promoção para release pública/latest. Uma release já pública é imutável: o rerun baixa exatamente os oito assets, rejeita ausências e extras, valida cada byte e somente atualiza as notas quando tudo é idêntico.

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
