/**
 * Join bytes with the given character.
 *
 * @param buf Buffer.
 * @param c Join character.  By default, just hex-encodes.
 * @returns Joined bytes.
 */
export function toHex(buf: Uint8Array, c = ''): string {
  return (Array
    .from(buf, b => b.toString(16).padStart(2, '0'))
    .join(c)
    .toUpperCase());
}

/**
 * Convert bytes to colon-separated.
 *
 * @param buf Buffer.
 * @returns 00:00:00.
 */
export function bytesToMac(buf: Uint8Array): string {
  return toHex(buf, ':');
}
