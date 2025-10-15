import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import crypto from 'node:crypto';

const DEFAULT_BASE_URL = process.env.INTERACTSH_BASE_URL ?? 'https://oast.pro';
const DEFAULT_DOMAIN_SUFFIX = process.env.INTERACTSH_DOMAIN_SUFFIX ?? new URL(DEFAULT_BASE_URL).hostname ?? '';
const AUTH_TOKEN = process.env.INTERACTSH_TOKEN;

export class InteractshSession {
  constructor({ correlationId, secretKey, privateKey, publicKeyB64, callbackDomain, serverUrl }) {
    this.correlationId = correlationId;
    this.secretKey = secretKey;
    this.privateKey = privateKey;
    this.publicKeyB64 = publicKeyB64;
    this.callbackDomain = callbackDomain;
    this.serverUrl = serverUrl;
  }

  toJSON() {
    return {
      correlation_id: this.correlationId,
      secret_key: this.secretKey,
      private_key_pem: this.privateKey.export({ type: 'pkcs8', format: 'pem' }),
      callback_domain: this.callbackDomain,
      server_url: this.serverUrl,
    };
  }
}

export class InteractshService {
  constructor(baseUrl, domainSuffix, token) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.domainSuffix = domainSuffix;
    this.token = token;
    this.sessions = new Map();
  }

  async createSession() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicExponent: 0x10001,
    });

    const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
    const publicKeyB64 = Buffer.from(publicKeyPem).toString('base64');
    const correlationId = this.#generateCorrelationId();
    const secretKey = this.#generateSecretKey();
    const callbackDomain = this.domainSuffix ? `${correlationId}.${this.domainSuffix}` : correlationId;

    const session = new InteractshSession({
      correlationId,
      secretKey,
      privateKey,
      publicKeyB64,
      callbackDomain,
      serverUrl: this.baseUrl,
    });

    await this.#register(session);
    this.sessions.set(correlationId, session);
    return session;
  }

  listSessions() {
    const result = {};
    for (const [key, session] of this.sessions.entries()) {
      result[key] = session.toJSON();
    }
    return result;
  }

  async pollSession(correlationId) {
    const session = this.#requireSession(correlationId);
    const url = new URL('/poll', this.baseUrl);
    url.searchParams.set('id', session.correlationId);
    url.searchParams.set('secret', session.secretKey);

    const response = await this.#request(url, { method: 'GET' });
    const payload = await response.json();

    const events = this.#decryptEvents(session.privateKey, payload);
    return {
      events,
      extra: normaliseArray(payload.extra),
      tld_data: normaliseArray(payload.tlddata),
    };
  }

  async deregisterSession(correlationId) {
    const session = this.#requireSession(correlationId);
    const url = new URL('/deregister', this.baseUrl);

    await this.#request(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        'correlation-id': session.correlationId,
        'secret-key': session.secretKey,
      }),
    });

    this.sessions.delete(correlationId);
  }

  async #register(session) {
    const url = new URL('/register', this.baseUrl);
    const payload = {
      'public-key': session.publicKeyB64,
      'secret-key': session.secretKey,
      'correlation-id': session.correlationId,
    };
    await this.#request(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
    });
  }

  async #request(url, options) {
    const headers = new Headers(options?.headers ?? {});
    if (this.token) {
      headers.set('Authorization', this.token);
    }
    const response = await fetch(url, { ...options, headers });
    if (!response.ok) {
      let message;
      try {
        const data = await response.json();
        message = data?.error || data?.message || JSON.stringify(data);
      } catch (err) {
        message = await response.text();
      }
      throw new Error(`interactsh responded ${response.status}: ${message}`);
    }
    return response;
  }

  #requireSession(correlationId) {
    const session = this.sessions.get(correlationId);
    if (!session) {
      throw new Error(`unknown correlation_id: ${correlationId}`);
    }
    return session;
  }

  #decryptEvents(privateKey, payload) {
    const encryptedEvents = normaliseArray(payload.data);
    if (!encryptedEvents.length) {
      return [];
    }
    const aesKeyB64 = payload.aes_key;
    if (!aesKeyB64) {
      return [];
    }
    const aesKey = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      Buffer.from(aesKeyB64, 'base64'),
    );

    return encryptedEvents.map((item) => decryptPayload(aesKey, item));
  }

  #generateCorrelationId() {
    // 10 bytes → 20 lowercase hex characters, matching interactsh defaults.
    return crypto.randomBytes(10).toString('hex');
  }

  #generateSecretKey() {
    return crypto
      .randomBytes(18)
      .toString('base64')
      .replace(/[^a-zA-Z0-9]/g, '')
      .slice(0, 24);
  }
}

function decryptPayload(aesKey, payloadB64) {
  const data = Buffer.from(payloadB64, 'base64');
  const iv = data.subarray(0, 16);
  const ciphertext = data.subarray(16);
  const decipher = crypto.createDecipheriv('aes-256-cfb', aesKey, iv);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plaintext.toString('utf8');
}

function normaliseArray(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value.map((item) => String(item));
  return [String(value)];
}

function applyEventFilters(events, filters) {
  if (!events.length) {
    return [];
  }

  const methodFilter = filters.method ? filters.method.toUpperCase() : undefined;
  const protocolFilter = filters.protocol ? filters.protocol.toLowerCase() : undefined;
  const pathFilter = filters.path_contains ? filters.path_contains.toLowerCase() : undefined;
  const queryFilter = filters.query_contains ? filters.query_contains.toLowerCase() : undefined;
  const textFilter = filters.text_contains ? filters.text_contains.toLowerCase() : undefined;

  return events
    .map((raw) => {
      const parsed = parseEvent(raw);
      return { raw, ...parsed };
    })
    .filter(({ raw, parsed, http, protocol }) => {
      if (methodFilter && (!http || http.method !== methodFilter)) {
        return false;
      }
      if (pathFilter && (!http || !http.pathLower.includes(pathFilter))) {
        return false;
      }
      if (queryFilter && (!http || !http.queryLower.includes(queryFilter))) {
        return false;
      }
      if (protocolFilter && (!protocol || protocol.toLowerCase() !== protocolFilter)) {
        return false;
      }
      if (textFilter) {
        const haystack = [raw, parsed ? JSON.stringify(parsed) : '', http?.fullPath ?? '']
          .join(' ')
          .toLowerCase();
        if (!haystack.includes(textFilter)) {
          return false;
        }
      }
      return true;
    })
    .map(({ raw, parsed, http, protocol }) => ({
      raw,
      protocol: protocol ?? undefined,
      http: http ?? undefined,
      parsed: parsed ?? undefined,
    }));
}

function parseEvent(eventString) {
  try {
    const data = JSON.parse(eventString);
    const protocol = typeof data.protocol === 'string' ? data.protocol : undefined;
    const rawRequest = data['raw-request'] ?? data.rawRequest ?? undefined;
    const http = extractHttpDetails(rawRequest);
    return { parsed: data, http, protocol };
  } catch (error) {
    return { parsed: undefined, http: undefined, protocol: undefined };
  }
}

function extractHttpDetails(rawRequest) {
  if (typeof rawRequest !== 'string') {
    return undefined;
  }
  const match = rawRequest.match(/^([A-Z]+)\s+(\S+)/m);
  if (!match) {
    return undefined;
  }
  const [, method, rawPath] = match;
  const [path, query = ''] = rawPath.split('?');
  return {
    method,
    path,
    query,
    fullPath: rawPath,
    pathLower: path.toLowerCase(),
    queryLower: query.toLowerCase(),
  };
}

function result(structured) {
  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(structured, null, 2),
      },
    ],
    structuredContent: structured,
  };
}

export async function main() {
  const service = new InteractshService(DEFAULT_BASE_URL, DEFAULT_DOMAIN_SUFFIX, AUTH_TOKEN);

  const server = new McpServer({
    name: 'interactsh-bridge',
    version: '0.1.0',
  });

  server.registerTool(
    'create_interactsh_session',
    {
      title: 'Create interactsh session',
      description: 'Generates credentials, registers with interactsh, and returns the connection details.',
    },
    async () => {
      const session = await service.createSession();
      const baseDomain = service.domainSuffix || new URL(service.baseUrl).hostname;
      const probeNonce = crypto
        .randomBytes(16)
        .toString('base64')
        .replace(/[^a-z0-9]/gi, '')
        .slice(0, 13)
        .toLowerCase();
      const probeHost = `${session.correlationId}${probeNonce}.${baseDomain}`;
      const instructions = [
        'Probing rules (very important):',
        '- Build the host as: <correlation_id><nonce13>.<domain>',
        '- correlation_id: exactly 20 lowercase hex characters (do not alter or truncate).',
        "- nonce13: exactly 13 lowercase alphanumeric characters [a-z0-9] (no hyphens or uppercase).",
        '- The label before the first dot must be length 33 (20 + 13).',
        '- Requests to only <correlation_id>.<domain> (no nonce) will be ignored by interactsh.',
        '',
        `Quick test (HTTP recommended): curl -I http://${probeHost}/`,
        'Then wait 2–3 seconds and call poll_interactsh_session with the same correlation_id to retrieve events.',
        'If you still get zero events, send another probe or use filters (method, protocol, path_contains, text_contains) when polling.',
      ].join('\n');

      return result({
        ...session.toJSON(),
        instructions,
        sample_probe_host: probeHost,
      });
    },
  );

  server.registerTool(
    'list_interactsh_sessions',
    {
      title: 'List sessions',
      description: 'Lists interactsh sessions cached in memory.',
    },
    async () => result(service.listSessions()),
  );

  server.registerTool(
    'poll_interactsh_session',
    {
      title: 'Poll session',
      description:
        'Retrieves and decrypts interactions for a session. Optional filters let you match HTTP method, path, query, protocol, or free text.',
      inputSchema: {
        correlation_id: z.string(),
        method: z.string().optional(),
        path_contains: z.string().optional(),
        query_contains: z.string().optional(),
        protocol: z.string().optional(),
        text_contains: z.string().optional(),
      },
    },
    async ({ correlation_id, ...filters }) => {
      const payload = await service.pollSession(correlation_id);
      const sanitizedFilters = Object.fromEntries(
        Object.entries(filters)
          .filter(([, value]) => value !== undefined && value !== '')
          .map(([key, value]) => [key, typeof value === 'string' ? value : JSON.stringify(value)]),
      );
      const filteredEvents = applyEventFilters(payload.events, sanitizedFilters);

      return result({
        applied_filters: sanitizedFilters,
        total_events: payload.events.length,
        matched_events: filteredEvents.length,
        events: filteredEvents,
        extra: payload.extra,
        tld_data: payload.tld_data,
      });
    },
  );

  server.registerTool(
    'deregister_interactsh_session',
    {
      title: 'Deregister session',
      description: 'Removes a session from interactsh and local cache.',
      inputSchema: { correlation_id: z.string() },
    },
    async ({ correlation_id }) => {
      await service.deregisterSession(correlation_id);
      return result({ status: 'deregistered', correlation_id });
    },
  );

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}
