"""
Verificador de prontidao para criptografia pos-quantica (PQC) — versao
Python.

CONTEXTO (verificado em setembro/2026): o suporte a troca de chaves TLS
pos-quantica (grupo hibrido X25519MLKEM768, ML-KEM-768 finalizado pelo
NIST em FIPS 203) depende da versao do OpenSSL vinculada ao interpretador
Python em uso (modulo `ssl`), que normalmente segue o OpenSSL do sistema
operacional -- ao contrario do Node.js, que embute seu proprio OpenSSL.
Isso significa que, no Python, a prontidao para PQC varia MUITO conforme
o SO/distribuicao e normalmente exige atualizar o OpenSSL do sistema
(e possivelmente recompilar o Python contra ele), nao apenas atualizar
uma biblioteca.

HONESTIDADE TECNICA: assim como no motor Node, isto verifica apenas a
capacidade de SAIDA (conexoes TLS que o proprio processo Python faz,
ex: chamadas as APIs externas do .dimma). Para o trafego de ENTRADA dos
usuarios da aplicacao, a criptografia pos-quantica depende de onde o TLS
e terminado -- tipicamente um proxy reverso ou CDN, nao o processo
Python/Flask em si.
"""
import ssl

MIN_OPENSSL_MAJOR = 3
MIN_OPENSSL_MINOR = 5


def check_pqc_readiness() -> dict:
    version_info = ssl.OPENSSL_VERSION_INFO  # (major, minor, patch, ...)
    major, minor = version_info[0], version_info[1]

    ready = major > MIN_OPENSSL_MAJOR or (major == MIN_OPENSSL_MAJOR and minor >= MIN_OPENSSL_MINOR)

    guidance = []
    if ready:
        guidance.append(
            "O OpenSSL vinculado ao seu interpretador Python ja suporta troca de chaves "
            "pos-quantica. Se sua lib TLS/HTTP usa o modulo ssl padrao (ex: requests, "
            "urllib3 recentes), conexoes de SAIDA podem negociar o grupo hibrido "
            "automaticamente quando o servidor remoto tambem suportar."
        )
    else:
        guidance.append(
            f"O OpenSSL do seu ambiente ({ssl.OPENSSL_VERSION}) e anterior a 3.5 e NAO "
            "suporta troca de chaves pos-quantica. Diferente do Node.js (que embute seu "
            "proprio OpenSSL), o Python normalmente usa o OpenSSL do sistema operacional -- "
            "e preciso atualizar o OpenSSL do SO (e possivelmente reinstalar/recompilar o "
            "Python contra a versao nova) para obter isso."
        )

    guidance.append(
        "IMPORTANTE: isto cobre apenas conexoes de SAIDA feitas pelo processo Python. "
        "Para o trafego de ENTRADA dos seus usuarios, a criptografia pos-quantica depende "
        "de onde o TLS termina -- normalmente um proxy reverso ou CDN, nao o processo "
        "Flask em si:"
    )
    guidance.append("  - Cloudflare: ja suporta X25519MLKEM768 automaticamente, sem configuracao.")
    guidance.append(
        "  - Nginx: precisa ser compilado/linkado com OpenSSL 3.5+ e configurado com "
        '"ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;" (ou equivalente).'
    )
    guidance.append(
        "  - AWS ALB/ELB, outros load balancers gerenciados: consulte a documentacao do "
        "provedor para saber se e quando adicionaram suporte a grupos hibridos pos-quanticos."
    )

    return {
        "ready": ready,
        "python_version": ssl.OPENSSL_VERSION,
        "openssl_version": ssl.OPENSSL_VERSION,
        "group": "X25519MLKEM768",
        "scope": "saida (cliente TLS)",
        "guidance": guidance,
    }


def format_pqc_report(result: dict) -> str:
    lines = ["\ndimma pqc-check — prontidao para criptografia pos-quantica\n"]
    lines.append(f"OpenSSL vinculado ao Python: {result['openssl_version']}")
    lines.append(f"Grupo de troca de chaves alvo: {result['group']}")
    status = "PRONTO \u2705" if result["ready"] else "NAO PRONTO \u274C"
    lines.append(f"Status (conexoes de saida): {status}")
    lines.append("")
    lines.extend(result["guidance"])
    return "\n".join(lines)
