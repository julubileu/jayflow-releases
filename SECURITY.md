# Política de segurança

## Reporte privado

Para reportar uma vulnerabilidade, use **Security → Report a vulnerability** neste repositório e abra um GitHub Private Security Advisory. Não publique uma issue com detalhes exploráveis.

Inclua, quando possível:

- versão do JayFlow e sistema operacional;
- impacto observado e passos mínimos para reproduzir;
- nome e SHA-256 do artefato afetado;
- logs relevantes já redigidos.

Não envie tokens, chaves SSH, arquivos de credenciais, chave privada de assinatura, endereços privados ou dados de clientes. A confirmação e a coordenação de correção ocorrerão no advisory privado. A versão mais recente publicada é a versão suportada para correções de segurança.

## Assinatura das releases

As atualizações usam duas verificações complementares:

1. `latest.json` declara versão, URL e SHA-256 do executável portátil.
2. Uma assinatura Ed25519 autentica o par versão/digest; depois do download, o aplicativo também compara o SHA-256 dos bytes recebidos.

A chave pública Ed25519 é incorporada ao aplicativo no build. A chave privada fica em um secret do GitHub Actions, é fornecida ao assinador público compilado somente por variável de ambiente e não é gravada em arquivo, argumento de processo, log ou artefato. O job de build nunca contém esse secret: ele faz checkout/testa o fonte privado apenas com uma deploy key read-only e envia os quatro assets unsigned por artifact interno. O `jayflowd` auditado é transportado em um segundo artifact interno, separado de `dist` e nunca publicado. Outro job/runner faz checkout somente deste repositório público, testa e compila `cmd/release-tool`, baixa ambos os artifacts e, ainda sem o secret, analisa o ELF sem executá-lo e exige que todos os seus bytes estejam dentro do portátil. Só então os passos mínimos recebem a chave e derivam a chave pública para exigir correspondência exata com a variável pública configurada.

O auditor rejeita symlinks, FIFOs e qualquer entrada ou saída que não seja arquivo regular, e não segue links para fora do bundle. Ele também liga `buildinfo.txt` e o `vcs.revision` do Go à tag e ao SHA resolvidos no checkout. O epoch reprodutível vem do timestamp do mesmo commit; app e NSIS são construídos duas vezes com limpeza dos outputs entre builds e devem ser idênticos byte a byte. A validação estrutural do setup exige o `firstheader` canônico do NSIS no limite exato do overlay PE, além dos recursos de versão e do escopo por usuário.

`release-manifest.json` autentica com uma assinatura Ed25519 destacada em `release-manifest.sig` o nome, tamanho e SHA-256 de todos os artefatos distribuídos que podem executar ou declarar a proveniência: portátil, setup versionado, setup estável e `buildinfo.txt`. O `latest.json` continua usando exatamente o payload aceito pelo updater. `checksums.txt` cobre esses quatro arquivos e também os metadados/assinatura contra os bytes finais; ele auxilia a auditoria manual, mas a confiança de origem vem das assinaturas. O verificador público rejeita inventário extra ou ausente, JSON inesperado, assinatura inválida, tamanho divergente e qualquer hash divergente.

O workflow cria ou reutiliza somente um draft, envia todos os assets exceto `latest.json`, envia `latest.json` por último e só então promove a release a pública/latest. Em rerun de release já pública, baixa todos os oito nomes esperados, rejeita extras/ausentes e valida assinaturas, hashes e igualdade byte a byte. Conteúdo idêntico permite apenas atualizar notas; divergência falha como violação de imutabilidade. O workflow nunca apaga uma release.

## Limite: ausência de Authenticode

Ed25519 protege o canal de atualização e o manifesto da release, mas não é Authenticode. Os arquivos `.exe` atuais não são assinados com Authenticode porque isso exige um certificado de code signing e uma credencial privada separados. Assim, o Windows/SmartScreen ainda pode mostrar aviso do Windows. Não interprete `release-manifest.sig` ou `checksums.txt` como assinatura de editor reconhecida pelo Windows.

Se houver suspeita de comprometimento da chave, do workflow ou de um artefato, interrompa atualizações e faça o reporte privado imediatamente. A rotação da chave exige publicar um aplicativo confiável que contenha a nova chave pública; trocar apenas o manifesto não torna uma assinatura nova confiável para instalações existentes.
