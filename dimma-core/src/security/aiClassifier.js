'use strict';

const { consumeBudget } = require('./budget');

const DEFAULT_DAILY_BUDGET = 200;
const DEFAULT_TIMEOUT_MS = 5000;

const SYSTEM_PROMPT = `Voce e um classificador de seguranca ciberetica embutido no motor .dimma.
Voce recebe sinais de uma requisicao HTTP ja marcada como suspeita por uma camada local.
Decida se os sinais indicam um ataque real ou um falso positivo e responda ESTRITAMENTE
em JSON, sem texto extra, no formato:
{"malicious": true|false, "confidence": 0-1, "reason": "explicacao curta em portugues"}`;

const PROVIDERS = {
  nvidia: {
    apiKeyEnv: 'NVIDIA_API_KEY',
    modelEnv: 'NVIDIA_MODEL',
    defaultModel: 'meta/llama-3.1-8b-instruct',
    endpoint: () => process.env.NVIDIA_API_URL || 'https://integrate.api.nvidia.com/v1/chat/completions',
    label: 'NVIDIA NIM',
    format: 'openai',
  },
  openai: {
    apiKeyEnv: 'OPENAI_API_KEY',
    modelEnv: 'OPENAI_MODEL',
    defaultModel: 'gpt-4o-mini',
    endpoint: () => 'https://api.openai.com/v1/chat/completions',
    label: 'OpenAI',
    format: 'openai',
  },
  openrouter: {
    apiKeyEnv: 'OPENROUTER_API_KEY',
    modelEnv: 'OPENROUTER_MODEL',
    defaultModel: 'meta-llama/llama-3.1-8b-instruct',
    endpoint: () => 'https://openrouter.ai/api/v1/chat/completions',
    label: 'OpenRouter',
    format: 'openai',
  },
  anthropic: {
    apiKeyEnv: 'ANTHROPIC_API_KEY',
    modelEnv: 'ANTHROPIC_MODEL',
    defaultModel: 'claude-3-5-haiku-latest',
    endpoint: () => 'https://api.anthropic.com/v1/messages',
    label: 'Anthropic',
    format: 'anthropic',
  },
  gemini: {
    apiKeyEnv: 'GEMINI_API_KEY',
    modelEnv: 'GEMINI_MODEL',
    defaultModel: 'gemini-2.0-flash',
    endpoint: (model) =>
      `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`,
    label: 'Google Gemini',
    format: 'gemini',
  },
};

function resolveProviderConfig(options) {
  const provider = String(options.provider || process.env.DIMMA_AI_PROVIDER || 'nvidia').toLowerCase();
  const definition = PROVIDERS[provider];
  if (!definition) {
    throw new TypeError(`dimma-ai: provider invalido "${provider}".`);
  }

  const apiKey = options.apiKey || process.env[definition.apiKeyEnv];
  const model = options.model ||
    process.env.DIMMA_AI_MODEL ||
    process.env[definition.modelEnv] ||
    definition.defaultModel;

  return { provider, definition, apiKey, model };
}

function buildProviderRequest(provider, definition, model, apiKey, userMessage) {
  if (definition.format === 'anthropic') {
    return {
      url: definition.endpoint(model, apiKey),
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: {
        model,
        max_tokens: 300,
        temperature: 0,
        system: SYSTEM_PROMPT,
        messages: [{ role: 'user', content: userMessage }],
      },
    };
  }

  if (definition.format === 'gemini') {
    return {
      url: definition.endpoint(model, apiKey),
      headers: { 'Content-Type': 'application/json', 'x-goog-api-key': apiKey },
      body: {
        systemInstruction: { parts: [{ text: SYSTEM_PROMPT }] },
        contents: [{ role: 'user', parts: [{ text: userMessage }] }],
        generationConfig: { temperature: 0, maxOutputTokens: 300 },
      },
    };
  }

  const headers = {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${apiKey}`,
  };
  if (provider === 'openrouter') headers['X-Title'] = 'Dimma Security';

  return {
    url: definition.endpoint(model, apiKey),
    headers,
    body: {
      model,
      temperature: 0,
      max_tokens: 300,
      messages: [
        { role: 'system', content: SYSTEM_PROMPT },
        { role: 'user', content: userMessage },
      ],
    },
  };
}

function extractMessage(data, format) {
  if (format === 'anthropic') {
    return data && Array.isArray(data.content)
      ? data.content.find((part) => part.type === 'text')?.text
      : null;
  }
  if (format === 'gemini') {
    return data && data.candidates && data.candidates[0] &&
      data.candidates[0].content && data.candidates[0].content.parts &&
      data.candidates[0].content.parts.map((part) => part.text || '').join('');
  }
  return data && data.choices && data.choices[0] &&
    data.choices[0].message && data.choices[0].message.content;
}

function parseVerdict(messageContent) {
  if (typeof messageContent !== 'string' || !messageContent.trim()) {
    throw new Error('dimma-ai: resposta da IA sem conteudo de mensagem.');
  }

  const jsonMatch = messageContent.match(/\{[\s\S]*\}/);
  let parsed;
  try {
    parsed = JSON.parse(jsonMatch ? jsonMatch[0] : messageContent.trim());
  } catch {
    throw new Error('dimma-ai: nao foi possivel interpretar a resposta JSON da IA.');
  }

  if (
    !parsed ||
    typeof parsed.malicious !== 'boolean' ||
    typeof parsed.confidence !== 'number' ||
    !Number.isFinite(parsed.confidence) ||
    parsed.confidence < 0 ||
    parsed.confidence > 1 ||
    typeof parsed.reason !== 'string'
  ) {
    throw new Error('dimma-ai: resposta da IA fora do formato esperado.');
  }

  return {
    malicious: parsed.malicious,
    confidence: parsed.confidence,
    reason: parsed.reason.slice(0, 500),
  };
}

/**
 * Classifica apenas sinais minimizados; nao envie bodies, credenciais ou IPs.
 * @param {{findings: object[], rawInput: object, context?: object}} payload
 * @param {{provider?: string, model?: string, apiKey?: string, fetchImpl?: Function}} options
 */
async function classifyWithAI(payload, options = {}) {
  const { provider, definition, apiKey, model } = resolveProviderConfig(options);
  if (!apiKey) {
    return {
      malicious: null,
      confidence: 0,
      reason: `${definition.apiKeyEnv} nao configurada — IA nao consultada.`,
    };
  }

  const configuredBudget = Number(options.dailyBudget ?? process.env.DIMMA_AI_DAILY_BUDGET);
  const dailyBudget = Number.isSafeInteger(configuredBudget) && configuredBudget >= 0
    ? configuredBudget
    : DEFAULT_DAILY_BUDGET;
  const budget = await consumeBudget(`ai:${provider}`, dailyBudget);
  if (!budget.allowed) {
    return { malicious: null, confidence: 0, reason: 'Orcamento diario de chamadas de IA esgotado.' };
  }

  const fetchImpl = options.fetchImpl || fetch;
  const timeoutMs = Number.isFinite(options.timeoutMs) && options.timeoutMs > 0
    ? options.timeoutMs
    : DEFAULT_TIMEOUT_MS;
  const requestPayload = buildProviderRequest(
    provider,
    definition,
    model,
    apiKey,
    JSON.stringify(payload, null, 2)
  );
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    let response;
    try {
      response = await fetchImpl(requestPayload.url, {
        method: 'POST',
        headers: requestPayload.headers,
        body: JSON.stringify(requestPayload.body),
        signal: controller.signal,
      });
    } catch {
      if (controller.signal.aborted) {
        throw new Error(`dimma-ai: timeout na consulta a ${definition.label} (${timeoutMs} ms).`);
      }
      throw new Error(`dimma-ai: falha de conexao com ${definition.label}.`);
    }

    if (!response.ok) {
      throw new Error(`dimma-ai: falha na API ${definition.label} (${response.status}).`);
    }

    let data;
    try {
      data = await response.json();
    } catch {
      if (controller.signal.aborted) {
        throw new Error(`dimma-ai: timeout na consulta a ${definition.label} (${timeoutMs} ms).`);
      }
      throw new Error(`dimma-ai: resposta JSON invalida de ${definition.label}.`);
    }

    return parseVerdict(extractMessage(data, definition.format));
  } finally {
    clearTimeout(timeout);
  }
}

function aiReviewMiddleware(options = {}) {
  return async function dimmaAiReview(req, res, next) {
    const suspicious = req.dimmaAnomaly && req.dimmaAnomaly.anomalous;
    if (!suspicious) return next();

    try {
      const verdict = await classifyWithAI(
        {
          findings: [req.dimmaAnomaly],
          rawInput: { path: req.path, method: req.method },
        },
        {
          ...options,
          dailyBudget: options.maxCallsPerDay ?? options.dailyBudget,
        }
      );

      req.dimmaAiVerdict = verdict;
      if (
        verdict.malicious === true &&
        verdict.confidence >= (options.blockThreshold ?? 0.7)
      ) {
        return res.status(403).json({
          error: 'Requisicao bloqueada pelo .dimma apos analise de IA.',
          reason: verdict.reason,
        });
      }
    } catch (err) {
      // eslint-disable-next-line no-console
      console.warn('[dimma-ai] falha ao consultar IA, seguindo sem bloqueio adicional:', err.message);
    }

    return next();
  };
}

module.exports = { classifyWithAI, aiReviewMiddleware, PROVIDERS };
