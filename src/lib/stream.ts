export function bytesToStream(bytes: Uint8Array): ReadableStream {
  const { readable, writable } = new IdentityTransformStream();
  const writer = writable.getWriter();
  void writer
    .write(bytes)
    .then(() => writer.close())
    .catch(() => undefined);
  return readable;
}
