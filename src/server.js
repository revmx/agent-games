// Proof Gatekeeper agent for zkVerify Agent Games (agent: revmx).
// Transport: node:http. POST /agent is HMAC-SHA256 verified over the raw body
// (header x-agent-games-signature) before any JSON parsing; every response is
// signed the same way. Decisions are deterministic; proofs are Groth16 via
// snarkjs with the published gatekeeper circuit, which itself only admits the
// correct decision for the five in-circuit checks.
import { createServer } from 'node:http';
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { readFileSync, writeFileSync, renameSync, mkdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as snarkjs from 'snarkjs';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const PORT = Number(process.env.PORT || 8787);
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const TASK_ID_ENCODING = process.env.TASK_ID_ENCODING || 'keccak';
const DATA_DIR = process.env.DATA_DIR || join(ROOT, 'data');
const WASM = join(ROOT, 'circuits', 'gatekeeper.wasm');
const ZKEY = join(ROOT, 'circuits', 'gatekeeper_final.zkey');
const VK = JSON.parse(readFileSync(join(ROOT, 'circuits', 'gatekeeper_vk.json'), 'utf8'));

const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const mod = (x) => ((x % P) + P) % P;
const field = (x) => mod(BigInt(x)).toString();

const SIG_HEADER = 'x-agent-games-signature';
const REASONS = {
  VALID: 'VALID_CONDITION',
  PROOF_REUSED: 'PROOF_REUSED',
  VK_SUBSTITUTION: 'VK_SUBSTITUTION',
  THRESHOLD_MISMATCH: 'THRESHOLD_MISMATCH',
  EXPIRED_CONDITION: 'EXPIRED_CONDITION',
  RECIPIENT_MISMATCH: 'RECIPIENT_MISMATCH',
  AMOUNT_OVERFLOW: 'AMOUNT_OVERFLOW',
  MALFORMED: 'PUBLIC_INPUT_MISMATCH',
};

// ---------- HMAC ----------
function candidateKeys(secret) {
  if (!secret) return [];
  const keys = [Buffer.from(secret, 'utf8')];
  if (/^[0-9a-fA-F]{64}$/.test(secret.trim())) keys.push(Buffer.from(secret.trim(), 'hex'));
  return keys;
}
const KEYS = candidateKeys(SECRET);
const hmacHex = (key, body) => createHmac('sha256', key).update(body).digest('hex');
function verifyKey(rawBody, header) {
  if (!header || KEYS.length === 0) return null;
  const given = String(header).trim().replace(/^sha256=/i, '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(given)) return null;
  const givenBytes = Buffer.from(given, 'hex');
  for (const key of KEYS) {
    if (timingSafeEqual(Buffer.from(hmacHex(key, rawBody), 'hex'), givenBytes)) return key;
  }
  return null;
}

// ---------- persistent store (tasks for idempotent retries, seen proof refs per mode) ----------
mkdirSync(DATA_DIR, { recursive: true });
const STORE_PATH = join(DATA_DIR, 'store.json');
let store = { tasks: {}, seen: { practice: [], competition: [] } };
if (existsSync(STORE_PATH)) {
  try { store = JSON.parse(readFileSync(STORE_PATH, 'utf8')); } catch { /* start fresh */ }
}
store.tasks ??= {};
store.seen ??= { practice: [], competition: [] };
store.seen.practice ??= [];
store.seen.competition ??= [];
const seenSets = { practice: new Set(store.seen.practice), competition: new Set(store.seen.competition) };
function persist() {
  store.seen = { practice: [...seenSets.practice], competition: [...seenSets.competition] };
  const tmp = STORE_PATH + '.tmp';
  writeFileSync(tmp, JSON.stringify(store));
  renameSync(tmp, STORE_PATH);
}

// ---------- parsing ----------
const DECIMAL = /^[0-9]+$/;
const HEXRE = /^(0x)?[0-9a-fA-F]+$/;
function uint(v) {
  if (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0) return BigInt(v);
  if (typeof v === 'string' && DECIMAL.test(v.trim())) return BigInt(v.trim());
  throw new Error('bad uint');
}
function hexint(v) {
  if (typeof v === 'string' && HEXRE.test(v.trim())) {
    const s = v.trim();
    return BigInt(s.startsWith('0x') || s.startsWith('0X') ? s : '0x' + s);
  }
  throw new Error('bad hex');
}
function parseInput(raw) {
  if (typeof raw !== 'object' || raw === null) throw new Error('input not object');
  if (typeof raw.proof_tx !== 'string' || raw.proof_tx.trim() === '') throw new Error('proof_tx missing');
  return {
    registeredVk: hexint(raw.registered_vk),
    proofVk: hexint(raw.proof_vk),
    minimum: uint(raw.minimum),
    publicBalance: uint(raw.public_balance),
    expiryBlock: uint(raw.expiry_block),
    currentBlock: uint(raw.current_block),
    recipient: hexint(raw.recipient),
    conditionRecipient: hexint(raw.condition_recipient),
    amount: uint(raw.amount),
    maxTransfer: uint(raw.max_transfer),
    proofTx: raw.proof_tx,
  };
}

// ---------- decision (documented trap order; fail closed) ----------
function decide(input, alreadySeen) {
  if (alreadySeen) return ['REJECT', REASONS.PROOF_REUSED];
  if (input.proofVk !== input.registeredVk) return ['REJECT', REASONS.VK_SUBSTITUTION];
  if (input.publicBalance < input.minimum) return ['REJECT', REASONS.THRESHOLD_MISMATCH];
  if (input.currentBlock >= input.expiryBlock) return ['REJECT', REASONS.EXPIRED_CONDITION];
  if (input.recipient !== input.conditionRecipient) return ['REJECT', REASONS.RECIPIENT_MISMATCH];
  if (input.amount > input.maxTransfer) return ['REJECT', REASONS.AMOUNT_OVERFLOW];
  return ['APPROVE', REASONS.VALID];
}

// ---------- proving ----------
function taskIdField(taskId) {
  switch (TASK_ID_ENCODING) {
    case 'sha256': return field('0x' + bytesToHex(sha256(utf8ToBytes(taskId))));
    case 'ascii': return field('0x' + bytesToHex(utf8ToBytes(taskId)));
    case 'hex-digits': {
      const d = taskId.replace(/^gk_/, '').replace(/[^0-9a-fA-F]/g, '');
      return d === '' ? '0' : field('0x' + d);
    }
    default: return field('0x' + bytesToHex(keccak_256(utf8ToBytes(taskId)))); // keccak
  }
}
function circuitInputs(input, taskId, decision, salt) {
  return {
    minimum: field(input.minimum),
    publicBalance: field(input.publicBalance),
    amount: field(input.amount),
    maxTransfer: field(input.maxTransfer),
    recipient: field(input.recipient),
    conditionRecipient: field(input.conditionRecipient),
    expiryBlock: field(input.expiryBlock),
    currentBlock: field(input.currentBlock),
    taskId: taskIdField(taskId),
    salt: field(salt),
    decision: decision === 'APPROVE' ? '1' : '0',
    registeredVkHash: field(input.registeredVk),
    proofVkHash: field(input.proofVk),
  };
}
async function prove(inputs, budgetMs) {
  let timer;
  try {
    const timeout = new Promise((_, rej) => { timer = setTimeout(() => rej(new Error('prove timeout')), budgetMs); });
    const { proof, publicSignals } = await Promise.race([snarkjs.groth16.fullProve(inputs, WASM, ZKEY), timeout]);
    const ok = await snarkjs.groth16.verify(VK, publicSignals, proof);
    if (!ok) return null;
    return { proof, publicSignals };
  } catch {
    return null;
  } finally { clearTimeout(timer); }
}

// ---------- task handling ----------
const inFlight = new Map();
async function handleTask(envelope) {
  const taskId = typeof envelope.task_id === 'string' ? envelope.task_id : null;
  if (!taskId) return JSON.stringify({ decision: 'REJECT', reason_code: REASONS.MALFORMED });
  if (inFlight.has(taskId)) return inFlight.get(taskId);
  const work = answerTask(taskId, envelope).finally(() => inFlight.delete(taskId));
  inFlight.set(taskId, work);
  return work;
}

async function answerTask(taskId, envelope) {
  const mode = envelope.mode === 'competition' ? 'competition' : 'practice';
  const cached = store.tasks[taskId];
  if (cached?.responseBody) {
    console.log(JSON.stringify({ ev: 'task.retry', taskId, decision: cached.decision }));
    return cached.responseBody;
  }
  let input = null;
  try { input = parseInput(envelope.input); } catch { input = null; }
  if (!input) {
    const body = JSON.stringify({ decision: 'REJECT', reason_code: REASONS.MALFORMED });
    store.tasks[taskId] = { responseBody: body, decision: 'REJECT', mode };
    persist();
    return body;
  }
  const refKey = input.proofTx.trim().toLowerCase();
  const alreadySeen = seenSets[mode].has(refKey);
  const [decision, reasonCode] = decide(input, alreadySeen);
  const salt = cached?.salt || BigInt('0x' + randomBytes(31).toString('hex')).toString();
  const body = { decision, reason_code: reasonCode };

  // PROOF_REUSED carries no proof (excluded by the rules); all other verdicts are provable
  // because the circuit enforces exactly this decision for the five in-circuit checks.
  if (reasonCode !== REASONS.PROOF_REUSED) {
    const deadline = Date.parse(envelope.deadline_at || '');
    const budget = Number.isNaN(deadline) ? 20000 : Math.max(0, Math.min(20000, deadline - Date.now() - 1500));
    if (budget > 500) {
      const t = Date.now();
      const proved = await prove(circuitInputs(input, taskId, decision, salt), budget);
      if (proved) {
        body.proof = proved.proof;
        body.public_signals = proved.publicSignals;
        console.log(JSON.stringify({ ev: 'task.proved', taskId, ms: Date.now() - t }));
      } else {
        console.log(JSON.stringify({ ev: 'task.prove_failed', taskId }));
      }
    }
  }
  body.proof_tx = input.proofTx;
  const responseBody = JSON.stringify(body);
  if (decision === 'APPROVE') seenSets[mode].add(refKey);
  store.tasks[taskId] = { responseBody, decision, mode, salt };
  persist();
  console.log(JSON.stringify({ ev: 'task.answered', taskId, mode, decision, reasonCode, proof: 'proof' in body }));
  return responseBody;
}

// ---------- HTTP ----------
function send(res, status, body, key) {
  const headers = { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(body)) };
  if (key) headers[SIG_HEADER] = hmacHex(key, body);
  res.writeHead(status, headers).end(body);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => { size += c.length; if (size <= 1_000_000) chunks.push(c); });
    req.on('end', () => resolve(size > 1_000_000 ? null : Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

const server = createServer(async (req, res) => {
  try {
    if (req.method === 'GET' || req.method === 'HEAD') return send(res, 200, JSON.stringify({ ok: true }));
    if (req.method !== 'POST') return send(res, 405, JSON.stringify({ error: 'method not allowed' }));
    const raw = await readBody(req);
    if (raw === null) return send(res, 413, JSON.stringify({ error: 'body too large' }));
    const key = verifyKey(raw, req.headers[SIG_HEADER]);
    if (!key) {
      console.log(JSON.stringify({ ev: 'request.unauthorized', path: req.url, bytes: raw.length }));
      return send(res, 401, JSON.stringify({ error: 'invalid signature' }));
    }
    let envelope;
    try { envelope = JSON.parse(raw.toString('utf8')); } catch { return send(res, 400, JSON.stringify({ error: 'invalid json' }), key); }
    if (envelope?.type === 'agent-games.preflight.v1') {
      console.log(JSON.stringify({ ev: 'preflight', agentId: envelope.agent_id }));
      return send(res, 200, JSON.stringify({ ok: true, protocolVersion: 'v1' }), key);
    }
    if (envelope?.type === 'agent-games.proof-gatekeeper.v1') {
      return send(res, 200, await handleTask(envelope), key);
    }
    console.log(JSON.stringify({ ev: 'request.unknown_type', type: envelope?.type }));
    return send(res, 400, JSON.stringify({ error: 'unknown type' }), key);
  } catch (e) {
    console.log(JSON.stringify({ ev: 'request.error', error: String(e?.message || e) }));
    if (!res.headersSent) send(res, 500, JSON.stringify({ error: 'internal error' }));
  }
});

server.listen(PORT, () => {
  console.log(JSON.stringify({ ev: 'server.listening', port: PORT, taskIdEncoding: TASK_ID_ENCODING, hmacConfigured: KEYS.length > 0 }));
});
