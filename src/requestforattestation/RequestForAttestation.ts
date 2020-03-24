/**
 * Requests for attestation are a core building block of the KILT SDK.
 * A RequestForAttestation represents a [[Claim]] which needs to be validated. In practice, the RequestForAttestation is sent from a claimer to an attester.
 *
 * A RequestForAttestation object contains the [[Claim]] and its hash, and legitimations/delegationId of the attester.
 * It's signed by the claimer, to make it tamperproof (`claimerSignature` is a property of [[Claim]]).
 * A RequestForAttestation also supports hiding of claim data during a credential presentation.
 *
 * @packageDocumentation
 * @module RequestForAttestation
 * @preferred
 */
import { v4 as uuid } from 'uuid'
import { validateLegitimations, validateNoncedHash } from '../util/DataUtils'
import {
  verify,
  hash,
  coToUInt8,
  u8aToHex,
  u8aConcat,
  hashObjectAsStr,
} from '../crypto/Crypto'

import Identity from '../identity/Identity'
import AttestedClaim from '../attestedclaim/AttestedClaim'
import RequestForAttestationUtils from './RequestForAttestation.utils'
import IRequestForAttestation, {
  Hash,
  NonceHash,
  ClaimHashTree,
  CompressedRequestForAttestation,
} from '../types/RequestForAttestation'
import { IDelegationBaseNode } from '../types/Delegation'
import IClaim from '../types/Claim'
import Claim from '../claim/Claim'
import IAttestedClaim from '../types/AttestedClaim'

function hashNonceValue(nonce: string, value: string | object): string {
  return hashObjectAsStr(value, nonce)
}

function generateHash(value: string | object): NonceHash {
  const nonce: string = uuid()
  return {
    nonce,
    hash: hashNonceValue(nonce, value),
  }
}

function generateHashTree(contents: object): ClaimHashTree {
  const result: ClaimHashTree = {}

  Object.keys(contents).forEach(key => {
    result[key] = generateHash(contents[key])
  })

  return result
}

function verifyClaimerSignature(reqForAtt: IRequestForAttestation): boolean {
  return verify(
    reqForAtt.rootHash,
    reqForAtt.claimerSignature,
    reqForAtt.claim.owner
  )
}

function getHashRoot(leaves: Uint8Array[]): Uint8Array {
  const result = u8aConcat(...leaves)
  return hash(result)
}

export default class RequestForAttestation implements IRequestForAttestation {
  /**
   * [STATIC] Builds an instance of [[RequestForAttestation]], from a simple object with the same properties.
   * Used for deserialization.
   *
   * @param rfaInput - An object built from simple [[Claim]], [[Identity]] and legitimation objects.
   * @returns  A new [[RequestForAttestation]] `object`.
   * @example ```javascript
   * const serializedRequest =
   *   '{ "claim": { "cType": "0x981...", "contents": { "name": "Alice", "age": 29 }, owner: "5Gf..." }, ... }, ... }';
   * const parsedRequest = JSON.parse(serializedRequest);
   * RequestForAttestation.fromRequest(parsedRequest);
   * ```
   */
  public static fromRequest(
    rfaInput: IRequestForAttestation
  ): RequestForAttestation {
    return new RequestForAttestation(rfaInput)
  }

  /**
   * [STATIC] Builds a new instance of [[RequestForAttestation]], from a complete set of requiered parameters.
   *
   * @param claimInput - An `IClaim` object the request for attestation is built for.
   * @param identity - The Claimer's [Identity].
   * @param legitimationsInput - Array of [AttestedClaim] objects of the Attester which the Claimer requests to include into the attestation as legitimations.
   * @param delegationIdInput - The id of the DelegationNode of the Attester, which should be used in the attestation.
   * @returns  A new [[RequestForAttestation]] object.
   * @example ```javascript
   * const input = RequestForAttestation.fromClaimAndIdentity(claim, alice);
   * ```
   */
  public static fromClaimAndIdentity(
    claimInput: IClaim,
    identity: Identity,
    legitimationsInput: AttestedClaim[] = [],
    delegationIdInput: IDelegationBaseNode['id'] | null = null
  ): RequestForAttestation {
    if (claimInput.owner !== identity.address) {
      throw Error('Claim owner is not Identity')
    }
    const claimOwnerGenerated = generateHash(claimInput.owner)
    const cTypeHashGenerated = generateHash(claimInput.cTypeHash)
    const claimHashTreeGenerated = generateHashTree(claimInput.contents)
    const calculatedRootHash = RequestForAttestation.calculateRootHash(
      claimOwnerGenerated,
      cTypeHashGenerated,
      claimHashTreeGenerated,
      legitimationsInput,
      delegationIdInput
    )
    let legitimations: AttestedClaim[] = []
    if (Array.isArray(legitimationsInput)) {
      legitimations = legitimationsInput
    }
    return new RequestForAttestation({
      claim: claimInput,
      legitimations,
      claimOwner: claimOwnerGenerated,
      claimHashTree: claimHashTreeGenerated,
      cTypeHash: cTypeHashGenerated,
      rootHash: calculatedRootHash,
      claimerSignature: RequestForAttestation.sign(
        identity,
        calculatedRootHash
      ),
      delegationId: delegationIdInput,
    })
  }

  public static isIRequestForAttestation(
    // ughh that function name... how do we want to call these typeguards?
    input: IRequestForAttestation
  ): input is IRequestForAttestation {
    if (!input.claim || !Claim.isIClaim(input.claim)) {
      throw new Error('Claim not provided')
    }
    if (!input.legitimations || !Array.isArray(input.legitimations)) {
      throw new Error('Legitimations not provided')
    }
    if (!input.claimHashTree) {
      throw new Error('Claim Hash Tree not provided')
    } else {
      Object.keys(input.claimHashTree).forEach(key => {
        if (!input.claimHashTree[key].hash) {
          throw new Error('incomplete claim Hash Tree')
        }
      })
    }
    // implement verification of delegationId once chain connection is established
    if (
      typeof input.delegationId !== 'string' &&
      !input.delegationId === null
    ) {
      throw new Error('DelegationId not provided')
    }
    return RequestForAttestation.verifyData(input)
  }

  public claim: IClaim
  public legitimations: AttestedClaim[]
  public claimOwner: NonceHash
  public claimerSignature: string
  public claimHashTree: ClaimHashTree
  public cTypeHash: NonceHash
  public rootHash: Hash

  public delegationId: IDelegationBaseNode['id'] | null

  /**
   * Builds a new [[RequestForAttestation]] instance.
   *
   * @param requestForAttestationInput - The base object from which to create the input.
   * @example ```javascript
   * // create a new request for attestation
   * const reqForAtt = new RequestForAttestation(requestForAttestationInput);
   * ```
   */
  public constructor(requestForAttestationInput: IRequestForAttestation) {
    RequestForAttestation.isIRequestForAttestation(requestForAttestationInput)
    this.claim = requestForAttestationInput.claim
    this.claimOwner = requestForAttestationInput.claimOwner
    this.cTypeHash = requestForAttestationInput.cTypeHash
    if (
      typeof requestForAttestationInput.legitimations !== 'undefined' &&
      Array.isArray(requestForAttestationInput.legitimations) &&
      requestForAttestationInput.legitimations.length
    ) {
      this.legitimations = requestForAttestationInput.legitimations.map(
        legitimation => AttestedClaim.fromAttestedClaim(legitimation)
      )
    } else {
      this.legitimations = []
    }
    this.delegationId = requestForAttestationInput.delegationId
    this.claimHashTree = requestForAttestationInput.claimHashTree
    this.rootHash = requestForAttestationInput.rootHash
    this.claimerSignature = requestForAttestationInput.claimerSignature
  }

  /**
   * Removes [[Claim]] properties from the [[RequestForAttestation]] object, provides anonymity and security when building the [[createPresentation]] method.
   *
   * @param properties - Properties to remove from the [[Claim]] object.
   * @throws An error when a property which should be deleted wasn't found.
   * @example ```javascript
   * const rawClaim = {
   *   name: 'Alice',
   *   age: 29,
   * };
   * const claim = Claim.fromCTypeAndClaimContents(ctype, rawClaim, alice);
   * const reqForAtt = RequestForAttestation.fromClaimAndIdentity(
   *   claim,
   *   alice,
   *   [],
   *   null
   * );
   * reqForAtt.removeClaimProperties(['name']);
   * // reqForAtt does not contain `name` in its claimHashTree and its claim contents anymore.
   * ```
   */
  public removeClaimProperties(properties: string[]): void {
    properties.forEach(key => {
      if (!this.claimHashTree[key]) {
        throw Error(`Property '${key}' not found in claim`)
      }
      delete this.claim.contents[key]
      delete this.claimHashTree[key].nonce
    })
  }

  /**
   * Removes the [[Claim]] owner from the [[RequestForAttestation]] object.
   *
   * @example ```javascript
   * const reqForAtt = RequestForAttestation.fromClaimAndIdentity(
   *   claim,
   *   alice,
   *   [],
   *   null
   * );
   * reqForAtt.removeClaimOwner();
   * // `input` does not contain the claim `owner` or the `claimOwner`'s nonce anymore.
   * ```
   */
  public removeClaimOwner(): void {
    // should the resulting object pass isClaim and isRequestForAttestation?
    delete this.claim.owner
    delete this.claimOwner.nonce
  }

  /**
   * Verifies the data of the [[RequestForAttestation]] object; used to check that the data was not tampered with, by checking the data against hashes.
   *
   * @param input - The [[RequestForAttestation]] for which to verify data.
   * @returns Whether the data is valid.
   * @example ```javascript
   * const reqForAtt = RequestForAttestation.fromClaimAndIdentity(
   *   claim,
   *   alice,
   *   [],
   *   null
   * );
   * reqForAtt.verifyData(); // returns true if the data is correct
   * ```
   */
  public static verifyData(input: IRequestForAttestation): boolean {
    // check claim owner hash
    validateNoncedHash(input.claimOwner, input.claim.owner, 'Claim Owner')

    // check cType hash
    validateNoncedHash(
      input.cTypeHash,
      input.claim.cTypeHash,
      'Claim CType Hash'
    )

    // check all hashes for provided claim properties
    Object.keys(input.claim.contents).forEach(key => {
      const value = input.claim.contents[key]
      if (!input.claimHashTree[key]) {
        throw Error(`Property '${key}' not in claim hash tree`)
      }
      const hashed: NonceHash = input.claimHashTree[key]
      validateNoncedHash(hashed, value, `hash tree property ${key}`)
    })

    // check legitimations
    validateLegitimations(input.legitimations)

    // check claim hash
    if (
      input.rootHash !==
      RequestForAttestation.calculateRootHash(
        input.claimOwner,
        input.cTypeHash,
        input.claimHashTree,
        input.legitimations,
        input.delegationId
      )
    ) {
      throw new Error('Provided rootHash does not correspond to data')
    }
    // check signature
    if (!RequestForAttestation.verifySignature(input)) {
      throw new Error('Provided Signature not verifiable')
    }

    return true
  }

  /**
   * Verifies the signature of the [[RequestForAttestation]] object.
   *
   * @param input - [[RequestForAttestation]] .
   * @returns Whether the signature is correct.
   * @example ```javascript
   * const reqForAtt = RequestForAttestation.fromClaimAndIdentity(
   *   claim,
   *   alice,
   *   [],
   *   null
   * );
   * reqForAtt.verifySignature(); // returns `true` if the signature is correct
   * ```
   */
  public static verifySignature(input: IRequestForAttestation): boolean {
    return verifyClaimerSignature(input)
  }

  private static sign(identity: Identity, rootHash: Hash): string {
    return identity.signStr(rootHash)
  }

  private static getHashLeaves(
    claimOwner: NonceHash,
    cTypeHash: NonceHash,
    claimHashTree: object,
    legitimations: IAttestedClaim[],
    delegationId: IDelegationBaseNode['id'] | null
  ): Uint8Array[] {
    const result: Uint8Array[] = []
    result.push(coToUInt8(claimOwner.hash))
    result.push(coToUInt8(cTypeHash.hash))
    Object.keys(claimHashTree).forEach(key => {
      result.push(coToUInt8(claimHashTree[key].hash))
    })
    if (legitimations) {
      legitimations.forEach(legitimation => {
        result.push(coToUInt8(legitimation.attestation.claimHash))
      })
    }
    if (delegationId) {
      result.push(coToUInt8(delegationId))
    }

    return result
  }

  /**
   * Compresses an [[RequestForAttestation]] object from the [[compressRequestForAttestation]].
   *
   * @returns An array that contains the same properties of an [[RequestForAttestation]].
   */

  public compress(): CompressedRequestForAttestation {
    return RequestForAttestationUtils.compress(this)
  }

  /**
   * [STATIC] Builds an [[RequestForAttestation]] from the decompressed array.
   *
   * @returns A new [[RequestForAttestation]] object.
   */

  public static decompress(
    reqForAtt: CompressedRequestForAttestation
  ): RequestForAttestation {
    const decompressedRequestForAttestation = RequestForAttestationUtils.decompress(
      reqForAtt
    )
    return RequestForAttestation.fromRequest(decompressedRequestForAttestation)
  }

  private static calculateRootHash(
    claimOwner: NonceHash,
    cTypeHash: NonceHash,
    claimHashTree: object,
    legitimations: IAttestedClaim[],
    delegationId: IDelegationBaseNode['id'] | null
  ): Hash {
    const hashes: Uint8Array[] = RequestForAttestation.getHashLeaves(
      claimOwner,
      cTypeHash,
      claimHashTree,
      legitimations,
      delegationId
    )
    const root: Uint8Array =
      hashes.length === 1 ? hashes[0] : getHashRoot(hashes)
    return u8aToHex(root)
  }
}
