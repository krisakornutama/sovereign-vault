import { describe, expect, it } from 'vitest';
import { concatBytes, equalsConstantTime, toHex, utf8ToBytes } from '../src/index.js';

describe('byte helpers', () => {
  it('compares equal and different lengths', () => {
    expect(equalsConstantTime(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]))).toBe(true);
    expect(equalsConstantTime(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4]))).toBe(false);
    expect(equalsConstantTime(new Uint8Array([1]), new Uint8Array([1, 2]))).toBe(false);
  });

  it('concatenates and hex-encodes bytes', () => {
    const joined = concatBytes(utf8ToBytes('ab'), new Uint8Array(), utf8ToBytes('cd'));
    expect(new TextDecoder().decode(joined)).toBe('abcd');
    expect(toHex(new Uint8Array([0, 15, 255]))).toBe('000fff');
  });
});
