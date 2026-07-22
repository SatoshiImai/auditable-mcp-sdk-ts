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

/** Decode a standard base64 string to bytes. Throws if the input is not valid base64. */
export function base64ToBytes(text: string): Uint8Array {
  const binary = atob(text);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
