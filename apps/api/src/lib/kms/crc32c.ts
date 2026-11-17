/**
 * CRC32C (Castagnoli), as used by Cloud KMS to detect corruption of requests and
 * responses in transit. Not a security control on its own: AES-GCM inside KMS
 * provides authenticity; this catches bit flips between the app and KMS.
 */
const TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) c = c & 1 ? (c >>> 1) ^ 0x82f63b78 : c >>> 1;
    table[i] = c >>> 0;
  }
  return table;
})();

export function crc32c(data: Uint8Array): number {
  let c = 0xffffffff;
  for (const byte of data) c = TABLE[(c ^ byte) & 0xff]! ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
