# Política de segurança

## Reporte privado

Para reportar uma vulnerabilidade, use **Security → Report a vulnerability** neste repositório e abra um GitHub Private Security Advisory. Não publique uma issue com detalhes exploráveis.

Inclua, quando possível:

- versão do JayFlow e sistema operacional;
- impacto observado e passos mínimos para reproduzir;
- nome exato e SHA-256 do asset afetado;
- código de erro estável e sanitizado exibido pelo aplicativo;
- apenas o trecho mínimo de logs relevantes, já redigido.

Não envie tokens, cookies, chaves SSH, arquivos de credenciais, chave privada de assinatura, saída bruta de comandos, logs com segredos, endereços privados ou dados de clientes. A confirmação e a coordenação de correção ocorrerão no advisory privado. A versão mais recente publicada é a versão suportada para correções de segurança.

## Assinatura das releases

Os executáveis Windows e Linux têm manifestos de canal independentes:

1. `latest.json` declara versão, URL e SHA-256 do portátil Windows e assina `jayflow-update-v1\n<version>\n<sha256>\n`.
2. `linux-latest.json` declara versão, URL e SHA-256 do gateway Linux e assina `jayflow-linux-update-v1\n<version>\n<sha256>\n`.
3. Depois do download, cada updater recalcula o SHA-256 dos bytes recebidos e aceita somente a assinatura do seu próprio domínio.

Os canais usam o mesmo par Ed25519, mas uma assinatura Windows não pode ser reproduzida no canal Linux nem uma assinatura Linux no Windows. Essa separação impede replay entre protocolos; ela não limita o impacto do comprometimento da chave privada, que poderia assinar novos payloads nos dois domínios. A URL não integra o payload assinado: HTTPS protege sua entrega, enquanto versão e digest assinados fixam o executável aceito.

O comprometimento isolado de um token do GitHub ou de publicação pode adulterar ou substituir arquivos hospedados, mas não pode forjar nenhum dos dois manifestos sem a chave privada Ed25519. Clientes devem falhar diante de assinatura ou digest divergente. Isso não elimina a necessidade de interromper atualizações e investigar qualquer suspeita de comprometimento do repositório, workflow, token ou chave.

A chave pública Ed25519 é incorporada aos executáveis no build. A chave privada fica em um secret do GitHub Actions, é fornecida ao assinador público compilado somente por variável de ambiente e não é gravada em arquivo, argumento de processo, log ou artefato. Os jobs que constroem Windows e Linux e o job que executa a aceitação Linux têm `contents: read`: podem ler o fonte privado por uma deploy key read-only, mas não recebem a chave Ed25519 e não podem assinar nem publicar. A CI do repositório-fonte também é read-only e não pode enviar artefatos para uma release.

Somente o job final pode escrever a release. Ele faz checkout apenas deste repositório público e, portanto, não pode ler o fonte privado. Antes da exposição do secret, esse job testa e compila `cmd/release-tool`, reconcilia versão/ref/SHA dos builds e audita estaticamente os executáveis transportados. O ELF Linux nunca é executado no job que possui a chave privada. O `jayflowd` auditado é transportado em artifact interno separado, fora dos dez assets públicos, e nunca é publicado como arquivo independente.

O auditor rejeita symlinks, FIFOs e qualquer entrada ou saída que não seja arquivo regular, e não segue links para fora do bundle. Para Windows, ele liga `buildinfo.txt` e o `vcs.revision` do Go à tag e ao SHA resolvidos no checkout. O epoch reprodutível vem do timestamp do mesmo commit; aplicativo e setup NSIS são construídos duas vezes com limpeza dos outputs entre builds e devem ser idênticos byte a byte. A validação estrutural do setup exige o `firstheader` canônico do NSIS no limite exato do overlay PE, além dos recursos de versão e do escopo por usuário.

Para Linux, o build parte do checkout exato da tag, exige metadados VCS limpos (`vcs.modified=false`) e grava o `source_sha` validado no binário. A auditoria estática liga os bytes transportados a esse SHA e exige arquivo executável regular, ELF64 little-endian `x86-64`, módulo Go `github.com/julubileu/jayflow-v2/cmd/jayflow-web`, alvo `linux/amd64`, `CGO_ENABLED=0`, `-trimpath`, versão/SHA/chave pública estampados e `vcs.revision` idêntico. O job que possui o fonte executa `version --json`; jobs sem o fonte, especialmente o assinador, não executam o ELF transportado.

`release-manifest.json` autentica, por uma assinatura Ed25519 destacada em `release-manifest.sig`, o inventário agregado de cinco assets unsigned: portátil Windows, setup versionado, setup estável, `buildinfo.txt` e gateway Linux. Os quatro nomes Windows permanecem na ordem existente e o ELF é acrescentado como quinto item. Esse manifesto prova o conjunto; `latest.json` e `linux-latest.json` fixam independentemente o executável de cada canal e não são intercambiáveis.

`checksums.txt` cobre os cinco assets unsigned, os dois manifestos de canal, `release-manifest.json` e `release-manifest.sig`; ele não tenta conter o próprio hash. Ele auxilia a auditoria manual, mas a confiança de origem vem das assinaturas. O verificador público exige exatamente dez arquivos regulares e rejeita entrada extra ou ausente, JSON inesperado, assinatura inválida, tamanho divergente, ordem de checksums alterada ou qualquer hash divergente.

Quando houver uma publicação autorizada, o workflow cria ou reutiliza somente um draft, envia primeiro o conjunto que não é manifesto de canal, depois `latest.json` e por último `linux-latest.json`. Ele baixa novamente os dez arquivos e valida o bundle remoto antes de promover a release a pública/latest. Em rerun de release já pública, exige os dez nomes, assinaturas, hashes e igualdade byte a byte. Conteúdo idêntico permite apenas atualizar notas; ausência, extra ou divergência falha como violação de imutabilidade. O workflow nunca apaga uma release.

## Limite de segurança do host Linux

O gateway roda como serviço systemd do usuário, com `UMask=0077`, origem restrita ao loopback e permissão de escrita limitada a `~/.config/jayflow-web`, `~/.local/share/jayflow-web` e `~/.local/state/jayflow-web`. O fluxo mantém alvos versionados `current` e `previous`; uma nova versão só marca readiness depois de configuração, banco, autenticação, HTTP de loopback e ligação com o daemon estarem prontos. Se o marcador não surgir em 30 segundos, restaura `previous`, registra apenas uma razão sanitizada e sai com erro para o systemd iniciar o alvo restaurado.

Esse rollback protege disponibilidade contra uma atualização defeituosa; não é uma defesa contra um host já comprometido pelo mesmo usuário do serviço ou por `root`. O mesmo usuário pode controlar sua unit e modificar seus arquivos, e `root` pode alterar qualquer parte do sistema. Nessa situação, pare o serviço, preserve evidência, revogue credenciais e trate o host como comprometido; não confie no rollback local como recuperação de segurança.

Atualização e rollback do gateway nunca sinalizam, reiniciam, substituem ou removem `jayflowd`, sessões de agentes ou `~/.jayflow`. Recursos de conta, DNS e túnel da Cloudflare ficam fora da autoridade do updater: ele não os cria, altera nem exclui.

## Limite: ausência de Authenticode

Ed25519 protege os canais de atualização e o manifesto da release, mas não é Authenticode. Os arquivos `.exe` atuais não são assinados com Authenticode porque isso exige um certificado de code signing e uma credencial privada separados. Assim, o Windows/SmartScreen ainda pode mostrar aviso do Windows. Não interprete `release-manifest.sig` ou `checksums.txt` como assinatura de editor reconhecida pelo Windows.

A ausência de Authenticode é uma limitação específica dos executáveis Windows e não deve ser descrita como “assinar o ELF”. O gateway Linux não recebe uma assinatura embutida equivalente: sua autenticidade vem dos manifestos Ed25519, dos digests, da proveniência ligada ao `source_sha` e da auditoria estática do ELF.

Se houver suspeita de comprometimento da chave, do workflow ou de um artefato, interrompa atualizações e faça o reporte privado imediatamente. A rotação da chave exige publicar um aplicativo confiável que contenha a nova chave pública; trocar apenas o manifesto não torna uma assinatura nova confiável para instalações existentes.
