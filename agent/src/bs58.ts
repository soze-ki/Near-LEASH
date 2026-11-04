// Tiny base58 (Bitcoin alphabet) to avoid another dependency.
const A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function decode(s: string): Uint8Array {
  const bytes: number[] = [0];
  for (const c of s) {
    let carry = A.indexOf(c);
    if (carry < 0) throw new Error("bad base58");
    for (let i = 0; i < bytes.length; i++) {
      carry += bytes[i] * 58;
      bytes[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  for (const c of s) {
    if (c !== "1") break;
    bytes.push(0);
  }
  return Uint8Array.from(bytes.reverse());
}
export default { decode };
