/**
 * @packageDocumentation
 * @group integration/attestation
 * @ignore
 */

import { IAttestedClaim, IClaim } from '..'
import Attestation from '../attestation/Attestation'
import { revoke } from '../attestation/Attestation.chain'
import AttestedClaim from '../attestedclaim/AttestedClaim'
import { IBlockchainApi } from '../blockchain/Blockchain'
import {
  IS_IN_BLOCK,
  IS_READY,
  submitTxWithReSign,
} from '../blockchain/Blockchain.utils'
import { configuration } from '../config/ConfigService'
import getCached from '../blockchainApiConnection'
import Claim from '../claim/Claim'
import Credential from '../credential/Credential'
import CType from '../ctype/CType'
import {
  ERROR_ALREADY_ATTESTED,
  ERROR_CTYPE_NOT_FOUND,
} from '../errorhandling/ExtrinsicError'
import Identity from '../identity/Identity'
import RequestForAttestation from '../requestforattestation/RequestForAttestation'
import {
  CtypeOnChain,
  DriversLicense,
  IsOfficialLicenseAuthority,
  wannabeAlice,
  wannabeBob,
  wannabeFaucet,
  WS_ADDRESS,
} from './utils'

let blockchain: IBlockchainApi | undefined
let alice: Identity
beforeAll(async () => {
  blockchain = await getCached((configuration.host = WS_ADDRESS))
  alice = await Identity.buildFromURI('//Alice')
})

describe('handling attestations that do not exist', () => {
  it('Attestation.query', async () => {
    return expect(Attestation.query('0x012012012')).resolves.toBeNull()
  }, 30_000)

  it('Attestation.revoke', async () => {
    return expect(
      Attestation.revoke('0x012012012', alice).then((tx) =>
        submitTxWithReSign(tx, alice, { resolveOn: IS_IN_BLOCK })
      )
    ).rejects.toThrow()
  }, 30_000)
})

describe('When there is an attester, claimer and ctype drivers license', () => {
  let faucet: Identity
  let attester: Identity
  let claimer: Identity

  beforeAll(async () => {
    faucet = await wannabeFaucet
    attester = await wannabeAlice
    claimer = await wannabeBob

    const ctypeExists = await CtypeOnChain(DriversLicense)
    // console.log(`ctype exists: ${ctypeExists}`)
    // console.log(`verify stored: ${await DriversLicense.verifyStored()}`)
    if (!ctypeExists) {
      await DriversLicense.store(attester).then((tx) =>
        submitTxWithReSign(tx, attester, { resolveOn: IS_READY })
      )
    }
  }, 60_000)

  it('should be possible to make a claim', async () => {
    const content: IClaim['contents'] = { name: 'Ralph', age: 12 }
    const claim = Claim.fromCTypeAndClaimContents(
      DriversLicense,
      content,
      claimer.address
    )
    const {
      message: request,
    } = await RequestForAttestation.fromClaimAndIdentity(claim, claimer)
    expect(request.verifyData()).toBeTruthy()
    expect(request.claim.contents).toMatchObject(content)
  })

  it('should be possible to attest a claim', async () => {
    const content: IClaim['contents'] = { name: 'Ralph', age: 12 }

    const claim = Claim.fromCTypeAndClaimContents(
      DriversLicense,
      content,
      claimer.address
    )
    const {
      message: request,
    } = await RequestForAttestation.fromClaimAndIdentity(claim, claimer)
    expect(request.verifyData()).toBeTruthy()
    expect(request.verifySignature()).toBeTruthy()
    const attestation = Attestation.fromRequestAndPublicIdentity(
      request,
      attester.getPublicIdentity()
    )
    await attestation
      .store(attester)
      .then((tx) =>
        submitTxWithReSign(tx, attester, { resolveOn: IS_IN_BLOCK })
      )
    const cred = await Credential.fromRequestAndAttestation(
      claimer,
      request,
      attestation
    )
    const aClaim = cred.createPresentation([], false)
    expect(aClaim.verifyData()).toBeTruthy()
    await expect(aClaim.verify()).resolves.toBeTruthy()
  }, 60_000)

  it('should not be possible to attest a claim w/o tokens', async () => {
    const content: IClaim['contents'] = { name: 'Ralph', age: 12 }

    const claim = Claim.fromCTypeAndClaimContents(
      DriversLicense,
      content,
      claimer.address
    )
    const {
      message: request,
    } = await RequestForAttestation.fromClaimAndIdentity(claim, claimer)
    expect(request.verifyData()).toBeTruthy()
    expect(request.verifySignature()).toBeTruthy()
    const attestation = Attestation.fromRequestAndPublicIdentity(
      request,
      attester.getPublicIdentity()
    )

    const bobbyBroke = await Identity.buildFromMnemonic(
      Identity.generateMnemonic()
    )

    await expect(
      attestation.store(bobbyBroke).then((tx) =>
        submitTxWithReSign(tx, bobbyBroke, {
          resolveOn: IS_IN_BLOCK,
        })
      )
    ).rejects.toThrow()
    const cred = await Credential.fromRequestAndAttestation(
      bobbyBroke,
      request,
      attestation
    )
    const aClaim = cred.createPresentation([], false)

    await expect(aClaim.verify()).resolves.toBeFalsy()
  }, 60_000)

  it('should not be possible to attest a claim on a Ctype that is not on chain', async () => {
    const badCtype = CType.fromSchema({
      $id: 'kilt:ctype:0x1',
      $schema: 'http://kilt-protocol.org/draft-01/ctype#',
      title: 'badDriversLicense',
      properties: {
        name: {
          type: 'string',
        },
        weight: {
          type: 'integer',
        },
      },
      type: 'object',
    })

    const content: IClaim['contents'] = { name: 'Ralph', weight: 120 }
    const claim = Claim.fromCTypeAndClaimContents(
      badCtype,
      content,
      claimer.address
    )
    const {
      message: request,
    } = await RequestForAttestation.fromClaimAndIdentity(claim, claimer)
    const attestation = await Attestation.fromRequestAndPublicIdentity(
      request,
      attester.getPublicIdentity()
    )
    await expect(
      attestation.store(attester).then((tx) =>
        submitTxWithReSign(tx, attester, {
          resolveOn: IS_IN_BLOCK,
        })
      )
    ).rejects.toThrowError(ERROR_CTYPE_NOT_FOUND)
  }, 60_000)

  describe('when there is an attested claim on-chain', () => {
    let attClaim: AttestedClaim

    beforeAll(async () => {
      const content: IClaim['contents'] = { name: 'Rolfi', age: 18 }
      const claim = Claim.fromCTypeAndClaimContents(
        DriversLicense,
        content,
        claimer.address
      )
      const {
        message: request,
      } = await RequestForAttestation.fromClaimAndIdentity(claim, claimer)
      const attestation = Attestation.fromRequestAndPublicIdentity(
        request,
        attester.getPublicIdentity()
      )
      await attestation.store(attester).then((tx) =>
        submitTxWithReSign(tx, attester, {
          resolveOn: IS_IN_BLOCK,
        })
      )
      const cred = await Credential.fromRequestAndAttestation(
        claimer,
        request,
        attestation
      )
      attClaim = cred.createPresentation([], false)
      await expect(attClaim.verify()).resolves.toBeTruthy()
    }, 60_000)

    it('should not be possible to attest the same claim twice', async () => {
      await expect(
        attClaim.attestation.store(attester).then((tx) =>
          submitTxWithReSign(tx, attester, {
            resolveOn: IS_IN_BLOCK,
          })
        )
      ).rejects.toThrowError(ERROR_ALREADY_ATTESTED)
    }, 15_000)

    it('should not be possible to use attestation for different claim', async () => {
      const content = { name: 'Rolfi', age: 19 }
      const claim = Claim.fromCTypeAndClaimContents(
        DriversLicense,
        content,
        claimer.address
      )
      const {
        message: request,
      } = await RequestForAttestation.fromClaimAndIdentity(claim, claimer)
      const fakeAttClaim: IAttestedClaim = {
        request,
        attestation: attClaim.attestation,
      }

      await expect(AttestedClaim.verify(fakeAttClaim)).resolves.toBeFalsy()
    }, 15_000)

    it('should not be possible for the claimer to revoke an attestation', async () => {
      await expect(
        revoke(attClaim.getHash(), claimer).then((tx) =>
          submitTxWithReSign(tx, claimer, { resolveOn: IS_IN_BLOCK })
        )
      ).rejects.toThrowError('not permitted')
      await expect(attClaim.verify()).resolves.toBeTruthy()
    }, 45_000)

    it('should be possible for the attester to revoke an attestation', async () => {
      await expect(attClaim.verify()).resolves.toBeTruthy()
      await revoke(attClaim.getHash(), attester).then((tx) =>
        submitTxWithReSign(tx, attester, { resolveOn: IS_IN_BLOCK })
      )
      await expect(attClaim.verify()).resolves.toBeFalsy()
    }, 40_000)
  })

  describe('when there is another Ctype that works as a legitimation', () => {
    beforeAll(async () => {
      if (!(await CtypeOnChain(IsOfficialLicenseAuthority))) {
        await IsOfficialLicenseAuthority.store(faucet).then((tx) =>
          submitTxWithReSign(tx, faucet, { resolveOn: IS_IN_BLOCK })
        )
      }
      await expect(
        CtypeOnChain(IsOfficialLicenseAuthority)
      ).resolves.toBeTruthy()
    }, 45_000)

    it('can be included in a claim as a legitimation', async () => {
      // make credential to be used as legitimation
      const licenseAuthorization = Claim.fromCTypeAndClaimContents(
        IsOfficialLicenseAuthority,
        {
          LicenseType: "Driver's License",
          LicenseSubtypes: 'sportscars, tanks',
        },
        attester.address
      )
      const {
        message: request1,
      } = await RequestForAttestation.fromClaimAndIdentity(
        licenseAuthorization,
        attester
      )
      const licenseAuthorizationGranted = Attestation.fromRequestAndPublicIdentity(
        request1,
        faucet.getPublicIdentity()
      )
      await licenseAuthorizationGranted
        .store(faucet)
        .then((tx) =>
          submitTxWithReSign(tx, faucet, { resolveOn: IS_IN_BLOCK })
        )
      // make request including legitimation
      const iBelieveICanDrive = Claim.fromCTypeAndClaimContents(
        DriversLicense,
        { name: 'Dominic Toretto', age: 52 },
        claimer.address
      )
      const {
        message: request2,
      } = await RequestForAttestation.fromClaimAndIdentity(
        iBelieveICanDrive,
        claimer,
        {
          legitimations: [
            await Credential.fromRequestAndAttestation(
              attester,
              request1,
              licenseAuthorizationGranted
            ).then((e) => e.createPresentation([], false)),
          ],
        }
      )
      const LicenseGranted = Attestation.fromRequestAndPublicIdentity(
        request2,
        attester.getPublicIdentity()
      )
      await LicenseGranted.store(attester).then((tx) =>
        submitTxWithReSign(tx, attester, { resolveOn: IS_IN_BLOCK })
      )
      const license = await Credential.fromRequestAndAttestation(
        claimer,
        request2,
        LicenseGranted
      ).then((e) => e.createPresentation([], false))
      await Promise.all([
        expect(license.verify()).resolves.toBeTruthy(),
        expect(
          licenseAuthorizationGranted.checkValidity()
        ).resolves.toBeTruthy(),
      ])
    }, 70_000)
  })
})

afterAll(() => {
  if (typeof blockchain !== 'undefined') blockchain.api.disconnect()
})
