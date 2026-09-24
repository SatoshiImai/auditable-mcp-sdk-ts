/**
 * Standard base64 over bytes, using the universal `btoa`/`atob` globals (Node 16+, browsers, edge).
 * The detached signature is carried on the wire as standard base64, matching the Python SDK.
 */

/** Encode bytes as a standard base64 string. */
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

// Standard base64 exactly as §5.1 pins it: the alphabet of RFC 4648 §4, padded to a multiple of four.
// `atob` alone is laxer - it tolerates whitespace and missing padding - which would let this port
// accept a signature the Python port rejects, so the shape is checked before decoding.
const STANDARD_BASE64 = /^[A-Za-z0-9+/]*={0,2}$/;

/** Decode a standard base64 string to bytes. Throws if the input is not valid standard base64. */
export function base64ToBytes(text: string): Uint8Array {
  if (text.length % 4 !== 0 || !STANDARD_BASE64.test(text)) {
    throw new TypeError('not standard base64 (RFC 4648 §4, padded)');
  }
  const binary = atob(text);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
