import type {
  IAgentContext,
  IIdentifier,
  IKey,
  IKeyManager,
} from '@veramo/core-types'
import { bytesToHex } from '@veramo/utils'

/** BLS flows use an explicit key reference or the first managed BLS key. */
export function pickSigningKey(identifier: IIdentifier, keyRef?: string): IKey {
  const key = identifier.keys.find((candidate) =>
    keyRef ? candidate.kid === keyRef : candidate.type === 'Bls12381G1',
  )
  if (!key || key.type !== 'Bls12381G1')
    throw new Error(`key_not_found: No BLS signing key for ${identifier.did}`)
  return key
}

/** Encode bytes through the public keyManagerSign contract so schema validation works. */
export function wrapSigner(
  context: IAgentContext<Pick<IKeyManager, 'keyManagerSign'>>,
  key: IKey,
  algorithm?: string,
) {
  return async (data: string | Uint8Array): Promise<string> =>
    context.agent.keyManagerSign({
      keyRef: key.kid,
      data: typeof data === 'string' ? data : bytesToHex(data),
      encoding: typeof data === 'string' ? 'utf-8' : 'hex',
      algorithm,
    })
}
