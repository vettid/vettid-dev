/**
 * RFC 8785 (JSON Canonicalization Scheme) — minimal implementation.
 *
 * Why it matters: the PCR manifest and migration-config signatures
 * cover a JSON serialization. If the producer and verifier serialize
 * with different key orders or different whitespace, the signature
 * over byte-A doesn't match the byte-B that the verifier hashes —
 * silent signature failures even when the underlying values agree.
 *
 * Default `JSON.stringify` in V8 is order-by-insertion (deterministic
 * within one process, but you can't rely on it across producers). The
 * canonical form below is byte-for-byte identical no matter which
 * runtime emits it: keys sorted lexicographically (UTF-16 code unit
 * order, matching the JCS spec), no whitespace, numbers left as the
 * default V8 toString form.
 *
 * Notes:
 *   - JCS specifies a normalization for floating-point numbers
 *     (ES6 ToString). For our use case (integer fields like
 *     `version`, ISO-8601 timestamp strings, PCR hex strings) the
 *     default V8 number serialization is already canonical.
 *   - This implementation does not handle NaN / Infinity (neither
 *     does standard JSON; throws if encountered).
 */
export function canonicalize(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error('canonicalize: NaN/Infinity not representable in JSON');
    }
    return JSON.stringify(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalize).join(',') + ']';
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const parts: string[] = [];
    for (const k of keys) {
      const v = obj[k];
      if (v === undefined) continue; // strip undefined (matches JSON.stringify)
      parts.push(JSON.stringify(k) + ':' + canonicalize(v));
    }
    return '{' + parts.join(',') + '}';
  }
  if (typeof value === 'undefined') {
    throw new Error('canonicalize: undefined is not JSON-serializable');
  }
  throw new Error(`canonicalize: unsupported type ${typeof value}`);
}
