import * as gabi from '@kiltprotocol/portablegabi'
import AttestedClaim from '../attestedclaim/AttestedClaim'
import { factory as LoggerFactory } from '../config/ConfigService'
import CType from '../ctype/CType'
import {
  ERROR_MESSAGE_TYPE,
  ERROR_PE_VERIFICATION,
} from '../errorhandling/SDKErrors'
import Identity from '../identity/Identity'
import PublicAttesterIdentity from '../identity/PublicAttesterIdentity'
import Message, { IMessage, MessageBodyType } from '../messaging/Message'
import IAttestedClaim from '../types/AttestedClaim'
import IPublicIdentity from '../types/PublicIdentity'
import IRequestForAttestation from '../types/RequestForAttestation'

const log = LoggerFactory.getLogger('Verifier')

export interface IPresentationReq {
  properties: string[]
  ctypeHash?: CType['hash']
  legitimations?: boolean
  delegation?: boolean
  requestUpdatedAfter?: Date
}

export interface IPartialRequest {
  ctype: CType['hash'] | null
  properties: string[]
}

export interface IVerifierSession {
  privacyEnhancement: gabi.CombinedVerificationSession
  requestedProperties: IPartialRequest[]
  allowedPrivacyEnhancement: boolean
}

/**
 * A helper class to initiate a verification by creating a presentation request which is built
 * on a specific [[CType]] and attributes of the [[Claim]] the verifier requires to see.
 */
export class PresentationRequestBuilder {
  private builder: gabi.CombinedRequestBuilder
  private partialReq: IPartialRequest[]
  constructor() {
    this.builder = new gabi.CombinedRequestBuilder()
    this.partialReq = []
  }

  /**
   * Initiates a verification by creating a presentation request for a specific [[CType]].
   * Note that you are required to call [[finalize]] on the request to conclude it.
   *
   * @param p The parameter object.
   * @param p.ctypeHash The SHA-256 hash of the [[CType]].
   * @param p.properties A list of properties of the [[Credential]]s the verifier has to see in order to verify it.
   * @param p.legitimations An optional boolean representing whether the verifier requests to see the legitimations of the attesters which signed the [[Credential]]s.
   * @param p.delegation An optional boolean representing whether the verifier requests to see the attesters' unique delegation identifiers.
   * @param p.requestUpdatedAfter The optional minimum required timestamp on which the [[Credential]] needs to be updated.
   * The default value for this is the current date.
   * @returns A [[PresentationRequestBuilder]] on which you need to call [[finalize]] to complete the presentation request.
   */
  public requestPresentationForCtype({
    ctypeHash,
    properties,
    legitimations,
    delegation,
    requestUpdatedAfter = new Date(),
  }: IPresentationReq): PresentationRequestBuilder {
    // since we are building always a pe request, we need to translate the attribute names to
    // absolute property paths. The PE credential contains a RequestForAttestation
    const rawProperties = properties.map((attr) => `claim.contents.${attr}`)
    if (typeof ctypeHash !== 'undefined') {
      rawProperties.push('claim.cTypeHash')
    }
    if (legitimations === true) {
      rawProperties.push('legitimation')
    }
    if (delegation === true) {
      rawProperties.push('delegationId')
    }
    this.builder.requestPresentation({
      requestedAttributes: rawProperties,
      reqUpdatedAfter: requestUpdatedAfter,
    })
    this.partialReq.push({
      ctype: ctypeHash || null,
      properties: rawProperties,
    })
    return this
  }

  /**
   * [ASYNC] Concludes the presentation request.
   *
   * @param allowPE A boolean representing whether the verifier accepts a privacy enhanced presentation.
   * @param verifier The [[Identity]] of the verifier used to sign.
   * @param claimer The [[IPublicIdentity]] for which the message should be encrypted (note: the message will be return unencrypted. Use Message.getEncryptedMessage to encrypt the message).
   * @returns A session and a message object.
   * The **session** object will be used in [[verifyPresentation]] and should be kept private by the verifier.
   * The **message** object should be sent to the Claimer and used in [[createPresentation]].
   */
  public async finalize(
    allowPE: boolean,
    verifier: Identity,
    claimer: IPublicIdentity
  ): Promise<{
    session: IVerifierSession
    message: Message
  }> {
    const { session, message } = await this.builder.finalise()
    return {
      session: {
        privacyEnhancement: session,
        requestedProperties: this.partialReq,
        allowedPrivacyEnhancement: allowPE,
      },
      message: new Message(
        {
          type: MessageBodyType.REQUEST_CLAIMS_FOR_CTYPES,
          content: {
            ctypes: this.partialReq.map((pr) => pr.ctype),
            peRequest: message,
            allowPE,
          },
        },
        verifier,
        claimer
      ),
    }
  }
}

/**
 * Initiates a verification by creating a request on the Verifier's side.
 *
 * @returns A [[PresentationRequestBuilder]] based on a [[CType]] and a list of required disclosed attributes of the [[Credential]]s.
 */
export function newRequestBuilder(): PresentationRequestBuilder {
  return new PresentationRequestBuilder()
}

/**
 * Check that the submitted attestations fulfil our requested.
 *
 * @param attestedClaims The attested claims submitted by the claimer.
 * @param session The stored session object.
 * @returns An object describing whether the verification was successful.
 */
async function verifyPublicPresentation(
  attestedClaims: AttestedClaim[],
  session: IVerifierSession
): Promise<{
  verified: boolean
  claims: Array<Partial<IAttestedClaim>>
}> {
  if (attestedClaims.length !== session.requestedProperties.length) {
    log.info(
      `Rejected presentation because number of attested claims (${attestedClaims.length}) did not match number of requested claims (${session.requestedProperties.length}).`
    )
    return {
      verified: false,
      claims: [],
    }
  }

  const allVerified = await Promise.all(
    session.requestedProperties.map(async (requested, i) => {
      const ac = attestedClaims[i]
      const providedProperties = ac.getAttributes()
      // map the KILT Style properties to Gabi style properties
      const rawProperties = Array.from(providedProperties.keys()).map(
        (prop) => `claim.contents.${prop}`
      )
      // FIXME: types are strange. if you can remove them, the claim types are wrong...
      rawProperties.push('claim.cTypeHash')
      rawProperties.push('claim.owner')
      return (
        requested.properties.every((p) => {
          return rawProperties.includes(p)
        }) && ac.verify()
      )
    })
  )
  const verified = !allVerified.includes(false)
  return { verified, claims: verified ? attestedClaims : [] }
}

/**
 * Checks whether a given value is an array of which each entry is instance of an Accumulator.
 *
 * @param args Either an array or undefined which should be checked.
 * @returns True if typeguard is successful.
 */
function accumulatorArrTypeguard(
  args: gabi.Accumulator[] | unknown
): args is gabi.Accumulator[] {
  if (Array.isArray(args) && args.length) {
    return args.every((a) => a instanceof gabi.Accumulator)
  }
  return false
}

/**
 * Checks whether a given value is an array of which each entry is instance of a [[PublicAttesterIdentity]].
 *
 * @param args Either an array or undefined which should be checked.
 * @returns True if typeguard is successful.
 */
function publicAttesterArrTypeguard(
  args: PublicAttesterIdentity[] | unknown
): args is PublicAttesterIdentity[] {
  if (Array.isArray(args) && args.length) {
    return args.every((a) => a instanceof PublicAttesterIdentity)
  }
  return false
}

/**
 * [ASYNC] Verifies the Claimer's presentation of [[Credential]]s.
 *
 * @param message The Claimer's presentation of the [[Credential]]s that should be verified, the result of [[createPresentation]].
 * @param session The Verifier's private verification session created in [[finalize]].
 * @param _latestAccumulators The list of the latest accumulators for each Attester which signed a [[Credential]] of this presentation.
 * @param _attesterPubKeys The privacy enhanced public keys of all [[AttesterIdentity]]s which signed the [[Credential]]s.
 * @throws When either latestAccumulators or attesterPubKeys are undefined.
 * @throws [[ERROR_MESSAGE_TYPE]].
 * @returns An object containing the keys
 * **verified** (which describes whether the [[Credential]]s could be verified)
 * and **claims** (an array of [[Claim]]s restricted on the disclosed attributes selected in [[requestPresentationForCtype]]).
 */
export async function verifyPresentation(
  message: IMessage,
  session: IVerifierSession,
  _latestAccumulators?: gabi.Accumulator[],
  _attesterPubKeys?: PublicAttesterIdentity[]
): Promise<{
  verified: boolean
  claims: Array<Partial<IRequestForAttestation | IAttestedClaim>>
}> {
  // If we got a public presentation, check that the attestation is valid
  if (message.body.type === MessageBodyType.SUBMIT_CLAIMS_FOR_CTYPES_CLASSIC) {
    const attestedClaims = message.body.content.map(
      AttestedClaim.fromAttestedClaim
    )
    return verifyPublicPresentation(attestedClaims, session)
  }

  // if we got a privacy enhanced attestation, check that this was allowed by the verifier and
  // verify the attestation
  if (message.body.type === MessageBodyType.SUBMIT_CLAIMS_FOR_CTYPES_PE) {
    const accFailure = !accumulatorArrTypeguard(_latestAccumulators)
    const keyFailure = !publicAttesterArrTypeguard(_attesterPubKeys)
    if (accFailure || keyFailure) {
      throw ERROR_PE_VERIFICATION(accFailure, keyFailure)
    }
    if (session.allowedPrivacyEnhancement) {
      const latestAccumulators = _latestAccumulators as gabi.Accumulator[]
      const attesterPubKeys = (_attesterPubKeys as PublicAttesterIdentity[]).map(
        (ai: PublicAttesterIdentity) => ai.publicGabiKey
      )
      const {
        verified,
        claims,
      } = await gabi.Verifier.verifyCombinedPresentation({
        proof: message.body.content,
        verifierSession: session.privacyEnhancement,
        latestAccumulators,
        attesterPubKeys,
      })
      return { verified, claims }
    }
  } else {
    throw ERROR_MESSAGE_TYPE(
      message.body.type,
      MessageBodyType.SUBMIT_CLAIMS_FOR_CTYPES_CLASSIC,
      MessageBodyType.SUBMIT_CLAIMS_FOR_CTYPES_PE
    )
  }
  return { verified: false, claims: [] }
}
