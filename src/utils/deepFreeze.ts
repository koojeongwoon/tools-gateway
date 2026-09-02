/**
 * Recursively freezes an object and all of its nested properties to guarantee runtime immutability.
 * Conforms to pure Functional Programming (FP) and DDD value object guarantees.
 */
export function deepFreeze<T>(obj: T): Readonly<T> {
  if (obj === null || typeof obj !== "object") {
    return obj;
  }

  // Prevent circular freeze or freezing non-plain/special objects like RegExps/Buffers inappropriately
  if (obj instanceof RegExp || obj instanceof Date || Buffer.isBuffer(obj)) {
    return Object.freeze(obj);
  }

  if (Array.isArray(obj)) {
    for (const item of obj) {
      deepFreeze(item);
    }
    return Object.freeze(obj);
  }

  if (obj instanceof Map) {
    return Object.freeze(obj);
  }

  if (obj instanceof Set) {
    return Object.freeze(obj);
  }

  const propNames = Object.getOwnPropertyNames(obj) as (keyof T)[];
  for (const name of propNames) {
    const value = obj[name];
    if (value && typeof value === "object") {
      deepFreeze(value);
    }
  }

  return Object.freeze(obj);
}
