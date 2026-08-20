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

A chave pública Ed25519 é incorporada ao aplicativo no build. A chave privada fica em um secret do GitHub Actions, é fornecida ao assinador somente por variável de ambiente e não é gravada em arquivo, argumento de processo, log ou artefato. Antes do build, o workflow deriva a pública da privada e exige correspondência exata com a variável pública configurada no repositório.

Os hashes em `checksums.txt` ajudam na auditoria manual, mas não substituem a verificação da assinatura. `buildinfo.txt` e as notas da release vinculam os binários ao ref e ao SHA do código privado usado, sem conter secrets.

Se houver suspeita de comprometimento da chave, do workflow ou de um artefato, interrompa atualizações e faça o reporte privado imediatamente. A rotação da chave exige publicar um aplicativo confiável que contenha a nova chave pública; trocar apenas o manifesto não torna uma assinatura nova confiável para instalações existentes.
