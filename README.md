# JayFlow Releases

Este repositório público distribui os binários oficiais do JayFlow. O código-fonte e o processo de desenvolvimento ficam em um repositório privado; aqui permanecem somente o workflow auditável e os artefatos publicados.

## Instalação recomendada por usuário

O alvo deste contrato de release é `2.0.35-dev`, uma versão de desenvolvimento, não uma versão estável. Esta documentação não anuncia que a versão já foi publicada. Para Windows x64, baixe o [`JayFlow-setup.exe`](https://github.com/julubileu/jayflow-releases/releases/latest/download/JayFlow-setup.exe) correspondente à release que você pretende testar e execute-o. A página [Releases/latest](https://github.com/julubileu/jayflow-releases/releases/latest) mostra a versão efetivamente atual, notas, checksums e informações exatas do build.

O setup NSIS instala o JayFlow por usuário, em uma pasta gravável sem elevação administrativa, e mantém um nome estável para automação e documentação. Esse escopo é necessário para que o updater consiga substituir o executável ao lado da aplicação sem depender de privilégios de administrador ou de escrita em `Program Files`. O Windows pode solicitar a instalação ou atualização do Microsoft Edge WebView2, componente usado pela interface do JayFlow.

O destino padrão do setup é `%LOCALAPPDATA%\Programs\JayFlow`. O pipeline audita o gerador NSIS pinado, o PE produzido, o recurso de versão e o overlay estrutural do instalador. O overlay deve começar exatamente no fim das seções PE e conter o `firstheader` canônico do NSIS (`0xDEADBEEF` e `NullsoftInst`) com limites coerentes; renomear o portátil como setup não satisfaz essa prova. O `AppVersion` do aplicativo preserva a versão completa, inclusive o sufixo `-dev`; já o recurso numérico exigido pelo Windows tem quatro componentes `X.Y.Z.0`. Cada componente `X`, `Y` e `Z` é limitado a `0..65535`, e o formato numérico do Windows não comporta o sufixo `-dev`.

Os executáveis ainda **não têm assinatura Authenticode**. Authenticode exige um certificado de code signing separado da chave Ed25519 usada pelo updater. Portanto, o Windows/SmartScreen ainda pode exibir um aviso do Windows mesmo quando os hashes e as assinaturas Ed25519 abaixo forem válidos; este repositório não apresenta checksum Ed25519 como se fosse Authenticode.

## Executável portátil (uso avançado)

Cada release também contém `JayFlow-X.Y.Z.exe`. Essa edição portátil é útil para diagnóstico, teste controlado ou ambientes em que um instalador não pode ser usado. Coloque o arquivo em uma pasta gravável pelo usuário e preserve o nome versionado ao arquivá-lo.

O portátil não substitui as conveniências do setup. Se uma política corporativa bloquear o executável, peça a liberação pelo hash publicado em `checksums.txt`; não desative o antivírus ou as proteções do Windows.

## Gateway Mobile no Linux

O asset `jayflow-web-X.Y.Z-linux-amd64` é o gateway do JayFlow Mobile para Linux x86-64; ele não substitui o aplicativo desktop Windows nem o daemon `jayflowd`. O fluxo suportado chama `jayflow-web service install-unit` sem `sudo`, instala `jayflow-web.service` no systemd do usuário e gerencia estes caminhos fixos pertencentes somente ao gateway:

- configuração: `~/.config/jayflow-web/config.json`;
- unit: `~/.config/systemd/user/jayflow-web.service`;
- dados, releases e estado de atualização: `~/.local/share/jayflow-web`, incluindo `releases/current`, `releases/previous`, `update-pending.json` e `update-ok/`;
- estado operacional: `~/.local/state/jayflow-web`.

A unit executa somente `~/.local/share/jayflow-web/releases/current/jayflow-web`, usa `UMask=0077`, reinicia em caso de falha e recebe permissão de escrita apenas nos caminhos do próprio gateway. A origem HTTP/HTTPS do gateway fica restrita ao loopback; qualquer exposição por Cloudflare é uma etapa separada de provisionamento e administração da conta, fora do instalador e do updater.

Na instalação ou atualização, o fluxo suportado valida o artefato e seu digest assinado, executa o preflight offline, grava um executável em um diretório versionado e só então alterna atomicamente `previous` e `current`. Instalações externas reiniciam apenas o gateway com `systemctl --user restart jayflow-web.service`; uma atualização iniciada pelo próprio gateway faz `exec` do novo `current`, permanecendo sob supervisão da mesma unit.

O candidato tem 30 segundos para marcar readiness depois que configuração, banco de dados, autenticação, servidor de loopback e ligação com o daemon estiverem prontos. Se isso não ocorrer, o fluxo restaura `previous`, encerra uma vez com erro e deixa o systemd iniciar o alvo restaurado. Os binários versionados são retidos. Editar manualmente os links `current` ou `previous` não é um caminho de instalação, atualização ou rollback suportado.

Nem a atualização nem o rollback do gateway sinalizam, reiniciam, substituem ou removem `jayflowd`. Eles também não removem sessões de agentes, `~/.jayflow`, túneis, DNS ou outros recursos da conta Cloudflare.

## Atualizações assinadas

O aplicativo Windows consulta publicamente `latest.json`; o gateway Linux consulta somente `linux-latest.json`. Cada manifesto contém a versão, a URL e o SHA-256 do executável correspondente. Versão e digest são assinados com Ed25519, e cada cliente traz somente a chave pública e só aceita bytes cujo hash e assinatura sejam válidos.

`latest.json` continua exclusivo do Windows e assina `jayflow-update-v1\n<version>\n<sha256>\n`. `linux-latest.json` é exclusivo do gateway Linux e assina `jayflow-linux-update-v1\n<version>\n<sha256>\n`. Os dois canais usam o mesmo par de chaves, mas os domínios distintos impedem que uma assinatura válida de um canal seja reaproveitada no outro. A URL fica fora do payload assinado; HTTPS entrega o manifesto e o digest assinado fixa os bytes aceitos.

Não há PAT, chave privada ou credencial de GitHub embutida nos executáveis. O updater Windows não depende de túnel, porta adicional ou acesso da VM ao GitHub; o gateway Linux usa somente HTTPS de saída para ler sua release pública, sem credencial de GitHub e sem envolver Cloudflare. A chave privada de release existe somente como secret do workflow; o repositório usa uma deploy key separada e somente leitura para obter o código privado durante o build.

Cada release desse contrato tem exatamente dez arquivos regulares, sem diretórios, symlinks ou nomes adicionais:

- `JayFlow-X.Y.Z.exe`, portátil;
- `JayFlow-X.Y.Z-setup.exe` e `JayFlow-setup.exe`, dois nomes para os mesmos bytes finais do setup;
- `buildinfo.txt`, com tag, commit, versão Windows e escopo do instalador;
- `latest.json`, manifesto do updater com assinatura Ed25519 sobre `jayflow-update-v1\n<version>\n<sha256>\n`;
- `release-manifest.json` e sua assinatura destacada `release-manifest.sig`, que preservam os quatro itens Windows na ordem existente e acrescentam, como quinto item, o nome, tamanho e SHA-256 do ELF Linux;
- `checksums.txt`, que registra os SHA-256 dos cinco assets unsigned, dos dois manifestos de canal, de `release-manifest.json` e de `release-manifest.sig`. Ele não contém um auto-hash impossível;
- `jayflow-web-X.Y.Z-linux-amd64`, ELF64 estático para Linux/amd64, instalado como serviço de usuário pelo fluxo Mobile;
- `linux-latest.json`, manifesto exclusivo do gateway com assinatura Ed25519 sobre `jayflow-linux-update-v1\n<version>\n<sha256>\n`.

Assim, o manifesto agregado assinado autentica os cinco arquivos distribuídos como executáveis ou evidência de build, os dois manifestos de canal fixam seus executáveis de forma independente e `checksums.txt` reconcilia os outros nove arquivos. O inventário exato e a recomputação determinística fazem o verificador rejeitar qualquer byte ausente, extra ou divergente.

Os builds Windows e Linux, a aceitação Linux e a assinatura/publicação ocupam jobs/runners separados. Os jobs de build e aceitação recebem somente acesso read-only ao fonte privado e não podem publicar nem assinar. O `jayflowd` auditado viaja em artifact interno próprio, fora dos assets públicos, e nunca é publicado separadamente. O job final faz checkout somente deste repositório público, compila o auditor antes de receber a chave Ed25519 e inspeciona estaticamente os executáveis transportados; ele não executa o ELF Linux. Só depois dessas auditorias o secret é disponibilizado aos passos mínimos de derivação e assinatura.

A tag, o commit e os binários também são ligados entre si. `buildinfo.txt` deve conter exatamente a ref e o SHA validados, e o `vcs.revision` gravado pelo Go no portátil deve ser o mesmo SHA. O gateway transportado deve ser ELF64 little-endian `x86-64`, `linux/amd64`, executável, compilado com `CGO_ENABLED=0` e `-trimpath`, conter `vcs.modified=false` e o mesmo `source_sha`, e carregar a versão, o SHA da fonte e a chave pública estampados. O job que possui a fonte executa `version --json`; o job que possui a chave privada realiza apenas auditoria estática do ELF.

O pipeline deriva `SOURCE_DATE_EPOCH` do timestamp do mesmo commit e constrói os artefatos duas vezes a partir das mesmas entradas, com limpeza dos outputs e exigência de igualdade byte a byte. Apenas o segundo build é encaminhado para assinatura.

## Verificação manual

Baixe os dez assets da mesma release para um diretório sem arquivos extras. Obtenha a chave pública Ed25519 por um canal independente e confiável, por exemplo de um build JayFlow já confiável que a incorpora, e nunca de um arquivo baixado da própria release que está sendo verificada. A partir de um checkout confiável deste repositório, compile e verifique o bundle e o ELF Linux:

```bash
go build -trimpath -o ./jayflow-release-tool ./cmd/release-tool
./jayflow-release-tool verify-bundle \
  -version 2.0.35-dev \
  -dir /caminho/para/os/dez-assets \
  -portable-url https://github.com/julubileu/jayflow-releases/releases/download/v2.0.35-dev/JayFlow-2.0.35-dev.exe \
  -linux-url https://github.com/julubileu/jayflow-releases/releases/download/v2.0.35-dev/jayflow-web-2.0.35-dev-linux-amd64 \
  -public-key "$JAYFLOW_RELEASE_PUBLIC_KEY"

./jayflow-release-tool audit-linux \
  -version 2.0.35-dev \
  -path /caminho/para/os/dez-assets/jayflow-web-2.0.35-dev-linux-amd64 \
  -source-sha 0123456789abcdef0123456789abcdef01234567 \
  -public-key "$JAYFLOW_RELEASE_PUBLIC_KEY"
```

O SHA de 40 caracteres acima é apenas ilustrativo: substitua-o pelo `source_sha` publicado nas notas da release ou na evidência do build. `verify-bundle` rejeita arquivo ausente ou extra, valida as assinaturas Ed25519 do manifesto agregado e dos dois canais em seus domínios próprios, recalcula hashes e tamanhos, confere `checksums.txt`, exige que os dois setups sejam idênticos e compara cada manifesto de canal aos bytes do executável correspondente. `audit-linux` confirma estaticamente formato ELF, plataforma, `CGO_ENABLED=0`, `-trimpath`, VCS limpo, `source_sha` e marcadores estampados sem executar o arquivo transportado. Como conferência adicional sem autenticação de origem, `sha256sum -c checksums.txt` também pode ser usado dentro do diretório.

Quando uma publicação for autorizada, ela permanecerá como draft durante upload e verificação remota: primeiro o conjunto que não é manifesto de canal, depois `latest.json` e, por último, `linux-latest.json`. Somente um bundle remoto com os dez arquivos baixados novamente, verificados e idênticos poderá ser promovido para release pública/latest. Uma release já pública é imutável: um rerun rejeita ausências, extras ou bytes diferentes e somente pode atualizar as notas quando os dez assets forem idênticos.

## Requisitos da VM

O aplicativo desktop JayFlow continua instalado apenas no PC Windows. No fluxo Mobile, o gateway de usuário descrito acima roda no Linux; para usar agentes remotos, cadastre uma VM com:

- Linux x86-64 (`amd64`) acessível por SSH;
- autenticação SSH válida e chave do host verificável;
- subsistema SFTP habilitado na mesma conexão SSH;
- permissão de escrita do usuário em `~/.jayflow` e espaço livre para binário, logs e sessões;
- as CLIs que você pretende usar, como Claude Code ou Codex, instaladas e autenticadas para esse usuário.

O aplicativo desktop leva dentro de si o `jayflowd` Linux da mesma versão e o instala/atualiza em `~/.jayflow/bin` via SFTP. Não é necessário instalar o aplicativo desktop na VM, usar `sudo`, abrir uma porta TCP para o daemon ou criar um túnel reverso. Um reboot da VM encerra os processos e sessões que estavam em execução.

## Diagnóstico

Se a instalação ou conexão falhar:

1. Confira a versão e o SHA em `buildinfo.txt` e valide o arquivo com `checksums.txt` na página da release.
2. Abra o Activity Log do JayFlow e preserve a mensagem completa, removendo usuários, endereços e caminhos sensíveis antes de compartilhá-la.
3. Revise host, porta, usuário, autenticação SSH e eventual mudança da chave em `known_hosts`.
4. Confirme que o SFTP funciona e que o usuário consegue criar `~/.jayflow/bin` e `~/.jayflow/logs` sem `sudo`.
5. Na VM, confirme que a CLI escolhida está no `PATH` do usuário e já foi autenticada.

Problemas de integridade, assinatura ou atualização devem ser reportados pelo canal privado descrito em [SECURITY.md](SECURITY.md), e não em uma issue pública.
