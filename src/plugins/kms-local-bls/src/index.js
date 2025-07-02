/**
 * Provides a {@link https://github.com/jedisct1/libsodium.js | libsodium} backed
 * {@link @veramo/kms-local#KeyManagementSystem | key management system } and
 * {@link @veramo/kms-local#SecretBox | secret box } for the {@link @veramo/key-manager#KeyManager}
 *
 * @packageDocumentation
 */
export { BlsKeyManagementSystem } from './key-management-system-bls.js';
export { SecretBox } from './secret-box.js';
