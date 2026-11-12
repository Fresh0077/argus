/**
 * 计算文本的 SHA-256（小写十六进制）。
 *
 * 预览文本允许用户手动编辑，编辑后必须重新计算指纹；后端会用同一算法
 * 核对“用户确认的内容”与“实际发送的内容”是否一致。
 * localhost 属于安全上下文，`crypto.subtle` 可用。
 */
export async function sha256Hex(text: string): Promise<string> {
  if (!globalThis.crypto?.subtle) {
    throw new Error('当前浏览器不支持 SHA-256，无法确认预览内容。');
  }
  const digest = await globalThis.crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(text),
  );
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}
