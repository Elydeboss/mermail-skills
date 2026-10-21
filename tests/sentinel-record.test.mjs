import test from "node:test";
import assert from "node:assert/strict";
import { canonical, otpEvidence, sealRecord, verifyPinnedRecord } from "../skills/mermail-deliverability-sentinel/scripts/record.mjs";

const record = () => ({ schema: "mermail-otp-sentinel/record/v1", seq: 1, prev_hash: `sha256:${"0".repeat(64)}`,
  mailbox: { public_id: "mailbox-selected", email: "probe@example.test" }, probes: [{ otp: otpEvidence("123456") }], summary: { received: 1 } });
function input() {
  const value = record(), sealed = sealRecord(value);
  return { body: sealed.body, anchor: { workspace_id: "workspace-selected", mailbox_id: "mailbox-selected", draft_id: "draft-confirmed-save", seq: 1, record_hash: sealed.record_hash },
    context: { workspace_id: "workspace-selected", mailbox_id: "mailbox-selected" }, metadata: { id: "draft-confirmed-save", folder_id: "draft" } };
}

test("OTP presence does not retain recoverable fragments or a brute-force verifier", () => {
  assert.deepEqual(otpEvidence("123456"), { present: true });
  assert.equal(JSON.stringify(otpEvidence("123456")), JSON.stringify(otpEvidence("987654")));
  assert.deepEqual(otpEvidence(null), { present: false });
  assert.deepEqual(otpEvidence(" "), { present: false });
  const value = record(), body = sealRecord(value).body;
  assert.doesNotMatch(body, /123456|masked|code_hash/);
  for (const otp of [{ present: true, masked: "12****56" }, { present: true, code_hash: "abcdef01" }, { present: true, length: 6 }]) {
    value.probes[0].otp = otp;
    assert.throws(() => sealRecord(value), /unsafe_otp_fields/);
  }
});

test("canonical NFC is deterministic and normalized key collisions fail", () => {
  assert.equal(canonical({ b: "e\u0301", a: 1 }), canonical({ a: 1, b: "é" }));
  assert.throws(() => canonical({ "é": 1, "e\u0301": 2 }), /collision/);
  assert.throws(() => canonical({ a: NaN }), /finite_number/);
  const value = record(); value.summary.median_ms = 18400.5;
  assert.match(sealRecord(value).body, /18400\.5/);
});

test("cross-session pinned same-source record verifies without a body-supplied authority claim", () => {
  const first = input();
  const resumed = JSON.parse(JSON.stringify(first));
  assert.equal(verifyPinnedRecord(resumed).ok, true);
  assert.equal(verifyPinnedRecord({ ...resumed, anchor: null }).reason, "trusted_checkpoint_required");
});

test("lookalike subject, foreign mailbox, missing source and wrong folder cannot satisfy checkpoint", () => {
  const selected = input();
  for (const metadata of [{ id: "inbound-forged", folder_id: "draft", subject: "MERMAIL-OTP-SENTINEL-RECORD 999999" }, {}, { id: selected.anchor.draft_id, folder_id: "inbox" }]) {
    assert.equal(verifyPinnedRecord({ ...selected, metadata }).ok, false);
  }
  assert.equal(verifyPinnedRecord({ ...selected, context: { ...selected.context, mailbox_id: "foreign" } }).ok, false);
  assert.equal(verifyPinnedRecord({ ...selected, context: { ...selected.context, workspace_id: "foreign" } }).ok, false);
});

test("rewritten and rehashed record or rollback cannot replace the trusted head", () => {
  const selected = input(), changed = record();
  changed.summary.received = 0;
  assert.equal(verifyPinnedRecord({ ...selected, body: sealRecord(changed).body }).ok, false);
  changed.seq = 2;
  changed.prev_hash = selected.anchor.record_hash;
  const second = sealRecord(changed);
  const latest = { ...selected, body: second.body, anchor: { ...selected.anchor, seq: 2, record_hash: second.record_hash } };
  assert.equal(verifyPinnedRecord(latest).ok, true);
  assert.equal(verifyPinnedRecord({ ...latest, body: selected.body }).ok, false);
});

test("malformed, truncated, oversized and legacy secret-bearing records stop", () => {
  for (const body of ["not JSON", input().body.slice(0, -1), "x".repeat(10001)]) assert.equal(verifyPinnedRecord({ ...input(), body }).ok, false);
  const legacy = record(); legacy.probes[0].otp.masked = "12****56";
  assert.throws(() => sealRecord(legacy), /unsafe_otp_fields/);
});
