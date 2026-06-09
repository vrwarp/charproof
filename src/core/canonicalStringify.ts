/**
 * Canonical JSON stringification to ensure stable signatures.
 */
export function canonicalStringify(obj: any): string {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(item => canonicalStringify(item)).join(',') + ']';
  }
  const keys = Object.keys(obj)
    .filter(key => obj[key] !== undefined)
    .sort();
  // Keys are escaped via JSON.stringify (not raw-interpolated) so that keys
  // containing quotes or backslashes cannot produce ambiguous output that would
  // let two distinct objects canonicalize to the same string (signature collision).
  return '{' + keys.map(key => `${JSON.stringify(key)}:${canonicalStringify(obj[key])}`).join(',') + '}';
}
