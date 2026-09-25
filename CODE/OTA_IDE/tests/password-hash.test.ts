/**
 * Tests for the scrypt password scheme used by lib/auth.ts.
 *
 * hashPassword/verifyPassword are module-private, so this mirrors the exact
 * construction (`${salt}:${scrypt(password, salt, 64)}`, both hex) and pins the
 * properties that matter — including the length-mismatch case that used to
 * throw RangeError out of timingSafeEqual and surface as a 500 on login.
 */

import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';

function hashPassword(password: string, salt = crypto.randomBytes(16).toString('hex')) {
  return `${salt}:${crypto.scryptSync(password, salt, 64).toString('hex')}`;
}

function verifyPassword(password: string, storedHash: string) {
  const [salt, expected] = storedHash.split(':');
  if (!salt || !expected) return false;

  const actual = crypto.scryptSync(password, salt, 64).toString('hex');
  const actualBuffer = Buffer.from(actual, 'hex');
  const expectedBuffer = Buffer.from(expected, 'hex');
  if (actualBuffer.length !== expectedBuffer.length) return false;

  return crypto.timingSafeEqual(actualBuffer, expectedBuffer);
}

describe('password hashing', () => {
  it('accepts the correct password', () => {
    expect(verifyPassword('correct-horse-battery', hashPassword('correct-horse-battery'))).toBe(true);
  });

  it('rejects the wrong password', () => {
    const stored = hashPassword('correct-horse-battery');
    expect(verifyPassword('correct-horse-batterz', stored)).toBe(false);
    expect(verifyPassword('', stored)).toBe(false);
    expect(verifyPassword('CORRECT-HORSE-BATTERY', stored)).toBe(false);
  });

  it('salts each hash, so identical passwords do not collide', () => {
    expect(hashPassword('same')).not.toBe(hashPassword('same'));
  });

  it('stores a 16-byte salt and a 64-byte derived key, both hex', () => {
    const [salt, derived] = hashPassword('pw').split(':');
    expect(salt).toMatch(/^[0-9a-f]{32}$/);
    expect(derived).toMatch(/^[0-9a-f]{128}$/);
  });

  it('never stores the password itself', () => {
    expect(hashPassword('SuperSecret123!')).not.toContain('SuperSecret123!');
  });

  // Regression: these previously reached timingSafeEqual with mismatched
  // buffer lengths and threw instead of returning false.
  it.each([
    ['truncated hash', 'a'.repeat(32) + ':' + 'b'.repeat(64)],
    ['overlong hash', 'a'.repeat(32) + ':' + 'b'.repeat(256)],
    ['empty derived part', 'a'.repeat(32) + ':'],
  ])('returns false for a %s rather than throwing', (_label, stored) => {
    expect(() => verifyPassword('anything', stored)).not.toThrow();
    expect(verifyPassword('anything', stored)).toBe(false);
  });

  it.each([['no separator', 'nosalthere'], ['empty string', ''], ['only separator', ':']])(
    'returns false for a malformed record (%s)',
    (_label, stored) => {
      expect(verifyPassword('anything', stored)).toBe(false);
    },
  );
});
