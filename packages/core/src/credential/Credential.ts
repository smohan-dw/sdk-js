/**
 * Credentials are used to store attested claims. They can be used to create presentations of that credential.
 *
 * * There are two different ways of creating presentations. The simplest way is to create an [[AttestedClaim]].
 * * An attested claim can be linked to an identity and the verifier might be able to track the usage of that credential.
 * * When creating a presentation a privacy enhanced variant can be forced, which ensures that the identity of the claimer
 * * stays hidden and that the claimer cannot be tracked over multiple sessions.
 *
 * @packageDocumentation
 * @module Credential
 * @preferred
 */

import * as gabi from '@kiltprotocol/portablegabi'
import AttestedClaim from '../attestedclaim/AttestedClaim'
import Identity from '../identity/Identity'
import IAttestation from '../types/Attestation'
import ICredential from '../types/Credential'
import IRequestForAttestation from '../types/RequestForAttestation'
import { ERROR_IDENTITY_NOT_PE_ENABLED } from '../errorhandling/SDKErrors'

export default class Credential {
  /**
   * The request that was sent to the attester.
   */
  public readonly reqForAtt: IRequestForAttestation

  /**
   * The attestation received from the attester.
   */
  public readonly attestation: IAttestation

  /**
   * The privacy enhanced credential. This property is null, if no privacy enhanced attestation was issued by the attester.
   */
  public readonly privacyCredential: gabi.Credential | null

  /**
   * Build a [[Credential]] using an attestation. The credential can be used to create privacy enhanced presentations if a session and a privacy enhanced attestation is passed.
   *
   * @param claimer The owner of the credential.
   * @param request The request for attestation that was sent over to the attester.
   * @param attestation The attestation received from the attester.
   * @param session The session that was created while requesting the presentation.
   * @param attestationPE The privacy enhanced attestation which was created by the attester.
   *
   * @returns A credential that can be used to create presentations.
   */
  public static async fromRequestAndAttestation(
    claimer: Identity,
    request: IRequestForAttestation,
    attestation: IAttestation,
    session: gabi.ClaimerAttestationSession | null = null,
    attestationPE: gabi.Attestation | null = null
  ): Promise<Credential> {
    let privacyCredential: gabi.Credential | null = null

    if (session !== null && attestationPE !== null) {
      if (!claimer.claimer) {
        throw ERROR_IDENTITY_NOT_PE_ENABLED()
      }
      privacyCredential = await claimer.claimer.buildCredential({
        claimerSession: session,
        attestation: attestationPE,
      })
    }
    const copiedReq: IRequestForAttestation = {
      ...request,
      privacyEnhancement: null,
    }
    return new Credential({
      reqForAtt: copiedReq,
      attestation,
      privacyCredential,
    })
  }

  protected constructor({
    reqForAtt,
    attestation,
    privacyCredential,
  }: ICredential) {
    this.reqForAtt = reqForAtt
    this.attestation = attestation
    this.privacyCredential = privacyCredential
  }

  /**
   * Creates a public presentation which can be sent to a verifier.
   *
   * @param publicAttributes All properties of the claim which have been requested by the verifier and therefore must be publicly presented.
   * If kept empty, we hide all attributes inside the claim for the presentation.
   * @param excludeIdentity Whether or not to include the identity.
   *
   * @returns A public presentation.
   */
  public createPresentation(
    publicAttributes: string[],
    excludeIdentity = false
  ): AttestedClaim {
    const attClaim = new AttestedClaim(
      // clone the attestation and request for attestation because properties will be deleted later.
      // TODO: find a nice way to clone stuff
      JSON.parse(
        JSON.stringify({
          request: this.reqForAtt,
          attestation: this.attestation,
        })
      )
    )

    // remove requested from hidden attributes
    const excludedClaimProperties = this.whitelistAttributes(publicAttributes)

    // remove specific attributes
    attClaim.request.removeClaimProperties(excludedClaimProperties)
    if (excludeIdentity) {
      attClaim.request.removeClaimOwner()
    }
    return attClaim
  }

  /**
   * Get the names of all properties that are contained in the credential.
   *
   * @returns A set containing all property keys.
   */
  public getAttributes(): Set<string> {
    // TODO: move this to claim or contents
    return new Set(Object.keys(this.reqForAtt.claim.contents))
  }

  /**
   * Removes all requested attributes from the [[Credential]]s attributes.
   *
   * @param requestedAttributes The attributes which were requested by the verifier and therefore are publicly shown.
   *
   * @returns All attributes which can be hidden from the presentation.
   */
  private whitelistAttributes(requestedAttributes: string[]): string[] {
    // get clone of all attributes inside the credential as set
    const allAtts = this.getAttributes()

    // remove each requested attribute
    requestedAttributes.forEach((removeMe: string) => allAtts.delete(removeMe))
    return Array.from(allAtts)
  }
}
