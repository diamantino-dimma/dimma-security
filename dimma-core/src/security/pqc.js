'use strict';

/**
 * Verificador de prontidao para criptografia pos-quantica (PQC).
 *
 * CONTEXTO (verificado em setembro/2026): Node.js a partir das versoes
 * v22.20 (LTS) e v24.9.0 embute estaticamente o OpenSSL 3.5, que ja
 * negocia por padrao o grupo hibrido de troca de chaves
 * "X25519MLKEM768" (classico X25519 + ML-KEM-768, o padrao pos-quantico
 * finalizado pelo NIST em FIPS 203) em conexoes TLS de SAIDA (ex:
 * chamadas https para APIs externas como Anthropic/AbuseIPDB). Versoes
 * anteriores (Node 20, que embute OpenSSL 3.0.x) nao suportam isso.
 *
 * HONESTIDADE TECNICA IMPORTANTE: isto verifica a capacidade do runtime
 * Node como CLIENTE TLS (conexoes de saida que o proprio processo faz).
 * Para o trafego de ENTRADA dos usuarios da sua aplicacao, a criptografia
 * pos-quantica depende de onde o TLS e terminado -- normalmente um proxy
 * reverso ou CDN (Cloudflare ja suporta X25519MLKEM768 nativamente;
 * Nginx precisa ser compilado com OpenSSL 3.5+ e configurado
 * explicitamente). O .dimma nao pode magicamente adicionar PQC nessa
 * camada -- so pode diagnosticar e orientar.
 */

const MIN_OPENSSL_MAJOR = 3;
const MIN_OPENSSL_MINOR = 5;

function parseVersion(versionString) {
  const match = /^(\d+)\.(\d+)/.exec(versionString || '');
  if (!match) return null;
  return { major: Number(match[1]), minor: Number(match[2]) };
}

/**
 * @returns {{
 *   ready: boolean,
 *   nodeVersion: string,
 *   opensslVersion: string,
 *   group: string,
 *   scope: string,
 *   guidance: string[]
 * }}
 */
function checkPqcReadiness() {
  const nodeVersion = process.version;
  const opensslVersion = process.versions.openssl || 'desconhecida';
  const parsed = parseVersion(opensslVersion);

  const ready = Boolean(
    parsed && (parsed.major > MIN_OPENSSL_MAJOR || (parsed.major === MIN_OPENSSL_MAJOR && parsed.minor >= MIN_OPENSSL_MINOR))
  );

  const guidance = [];
  if (ready) {
    guidance.push(
      'Seu runtime Node ja negocia o grupo hibrido pos-quantico X25519MLKEM768 por padrao ' +
        'em conexoes TLS de SAIDA (ex: chamadas a APIs externas feitas pelo proprio .dimma, ' +
        'como AbuseIPDB/Anthropic). Nenhuma acao necessaria para essa parte.'
    );
  } else {
    guidance.push(
      `Seu OpenSSL embutido (${opensslVersion}) e anterior a 3.5 e NAO suporta troca de ` +
        'chaves pos-quantica. Atualize para Node.js >= 22.20 LTS ou >= 24.9.0 para obter ' +
        'isso automaticamente (o Node empacota seu proprio OpenSSL, entao normalmente basta ' +
        'atualizar o Node, sem mexer no sistema operacional).'
    );
  }

  guidance.push(
    'IMPORTANTE: isto cobre apenas conexoes de SAIDA feitas pelo processo Node. Para o ' +
      'trafego de ENTRADA dos seus usuarios, a criptografia pos-quantica depende de onde o ' +
      'TLS termina -- normalmente um proxy reverso ou CDN, nao o processo Node em si:'
  );
  guidance.push('  - Cloudflare: ja suporta X25519MLKEM768 automaticamente, sem configuracao.');
  guidance.push(
    '  - Nginx: precisa ser compilado/linkado com OpenSSL 3.5+ e configurado com ' +
      '"ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;" (ou equivalente).'
  );
  guidance.push(
    '  - AWS ALB/ELB, outros load balancers gerenciados: consulte a documentacao do provedor ' +
      'para saber se e quando adicionaram suporte a grupos hibridos pos-quanticos.'
  );

  return {
    ready,
    nodeVersion,
    opensslVersion,
    group: 'X25519MLKEM768',
    scope: 'saida (cliente TLS)',
    guidance,
  };
}

function formatPqcReport(result) {
  const lines = [];
  lines.push('\ndimma pqc-check — prontidao para criptografia pos-quantica\n');
  lines.push(`Node.js: ${result.nodeVersion}`);
  lines.push(`OpenSSL embutido: ${result.opensslVersion}`);
  lines.push(`Grupo de troca de chaves alvo: ${result.group}`);
  lines.push(`Status (conexoes de saida): ${result.ready ? 'PRONTO \u2705' : 'NAO PRONTO \u274C'}`);
  lines.push('');
  result.guidance.forEach((g) => lines.push(g));
  return lines.join('\n');
}

module.exports = { checkPqcReadiness, formatPqcReport };
