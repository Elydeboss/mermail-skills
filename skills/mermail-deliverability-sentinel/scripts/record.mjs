// Offline record/checkpoint checks only. No mailbox reads, secret store,
// authentication, persistent ledger, signing or effect authorization.
import { createHash } from "node:crypto";

const HASH = /^sha256:[0-9a-f]{64}$/;
const GENESIS = `sha256:${"0".repeat(64)}`;
const id = value => typeof value === "string" && value.length > 0 && value.length <= 200 && !/\s/u.test(value);

export function canonical(value) {
  let nodes = 0;
  const visit = (item, depth) => {
    if (++nodes > 2000 || depth > 24) throw Error("record_structure_bound");
    if (typeof item === "string") return JSON.stringify(item.normalize("NFC"));
    if (typeof item === "number") {
      if (!Number.isFinite(item) || Math.abs(item) > Number.MAX_SAFE_INTEGER) throw Error("record_finite_number_required");
      return JSON.stringify(item);
    }
    if (item === null || typeof item === "boolean") return JSON.stringify(item);
    if (Array.isArray(item)) return `[${item.map(x => visit(x, depth + 1)).join(",")}]`;
    if (!item || typeof item !== "object" || ![Object.prototype, null].includes(Object.getPrototypeOf(item))) throw Error("record_json_required");
    const keys = Object.keys(item).map(key => [key.normalize("NFC"), key]).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
    if (new Set(keys.map(([key]) => key)).size !== keys.length) throw Error("record_normalized_key_collision");
    return `{${keys.map(([key, raw]) => `${JSON.stringify(key)}:${visit(item[raw], depth + 1)}`).join(",")}}`;
  };
  return visit(value, 0);
}

export function otpEvidence(code) {
  if (code !== null && (typeof code !== "string" || code.length > 128)) throw Error("invalid_otp_observation");
  // No code fragments, code length, deterministic hash or derived identifier.
  return { present: code !== null && code.trim().length > 0 };
}

function validateRecord(record) {
  if (!record || record.schema !== "mermail-otp-sentinel/record/v1" || !Number.isSafeInteger(record.seq) || record.seq < 1
      || !HASH.test(record.prev_hash) || record.record_hash !== undefined
      || !id(record.mailbox?.public_id) || !Array.isArray(record.probes) || record.probes.length > 10) throw Error("invalid_record");
  if (record.seq === 1 && record.prev_hash !== GENESIS) throw Error("invalid_genesis");
  for (const probe of record.probes) {
    if (!probe?.otp || Object.keys(probe.otp).length !== 1 || typeof probe.otp.present !== "boolean") throw Error("unsafe_otp_fields");
  }
}

export function sealRecord(record) {
  validateRecord(record);
  const text = canonical(record);
  const record_hash = `sha256:${createHash("sha256").update(text, "utf8").digest("hex")}`;
  const body = `record_hash ${record_hash}\n${text}`;
  if (body.length > 10000) throw Error("record_body_bound");
  return { record_hash, body };
}

export function verifyPinnedRecord({ anchor, context, metadata, body }) {
  // The caller must obtain anchor from the authenticated user or an explicitly
  // selected private checkpoint produced by its own confirmed save/readback.
  // These checks cannot make mailbox text, a hash or an arbitrary file trusted.
  if (!anchor) return { ok: false, reason: "trusted_checkpoint_required" };
  if (![anchor.workspace_id, anchor.mailbox_id, anchor.draft_id].every(id) || !Number.isSafeInteger(anchor.seq)
      || anchor.seq < 1 || !HASH.test(anchor.record_hash)) return { ok: false, reason: "invalid_checkpoint" };
  if (context?.workspace_id !== anchor.workspace_id || context?.mailbox_id !== anchor.mailbox_id
      || metadata?.id !== anchor.draft_id || metadata?.folder_id !== "draft") return { ok: false, reason: "checkpoint_source_mismatch" };
  if (typeof body !== "string" || body.length > 10000) return { ok: false, reason: "record_body_bound" };
  try {
    const newline = body.indexOf("\n");
    if (newline < 0) throw Error("invalid_record_body");
    const record = JSON.parse(body.slice(newline + 1));
    const sealed = sealRecord(record);
    if (record.mailbox.public_id !== anchor.mailbox_id || record.seq !== anchor.seq
        || body !== sealed.body || sealed.record_hash !== anchor.record_hash) return { ok: false, reason: "checkpoint_record_mismatch" };
    return { ok: true, record_hash: sealed.record_hash, record };
  } catch {
    return { ok: false, reason: "invalid_or_unsafe_record" };
  }
}
