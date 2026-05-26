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
  return '{' + keys.map(key => `"${key}":${canonicalStringify(obj[key])}`).join(',') + '}';
}
