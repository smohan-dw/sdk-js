/**
 * @packageDocumentation
 * @ignore
 */

import { SubmittableExtrinsic } from '@polkadot/api/promise/types'
import { Option, Tuple } from '@polkadot/types'
import { getCached } from '../blockchainApiConnection'
import Identity from '../identity/Identity'
import IPublicIdentity from '../types/PublicIdentity'
import { IDid } from './Did'
import {
  decodeDid,
  getAddressFromIdentifier,
  getIdentifierFromAddress,
} from './Did.utils'

export async function queryByIdentifier(
  identifier: IDid['identifier']
): Promise<IDid | null> {
  const blockchain = await getCached()
  const address = getAddressFromIdentifier(identifier)
  const decoded = decodeDid(
    identifier,
    await blockchain.api.query.did.dIDs<Option<Tuple>>(address)
  )
  return decoded
}

export async function queryByAddress(
  address: IPublicIdentity['address']
): Promise<IDid | null> {
  const blockchain = await getCached()
  const identifier = getIdentifierFromAddress(address)
  const decoded = decodeDid(
    identifier,
    await blockchain.api.query.did.dIDs<Option<Tuple>>(address)
  )
  return decoded
}

export async function remove(
  identity: Identity
): Promise<SubmittableExtrinsic> {
  const blockchain = await getCached()
  const tx: SubmittableExtrinsic = blockchain.api.tx.did.remove()
  return blockchain.signTx(identity, tx)
}

export async function store(
  did: IDid,
  identity: Identity
): Promise<SubmittableExtrinsic> {
  const blockchain = await getCached()
  const tx: SubmittableExtrinsic = blockchain.api.tx.did.add(
    did.publicBoxKey,
    did.publicSigningKey,
    did.documentStore
  )
  return blockchain.signTx(identity, tx)
}
