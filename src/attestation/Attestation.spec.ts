import { Text, Data } from '@polkadot/types'
import Bool from '@polkadot/types/primitive/Bool'
import AccountId from '@polkadot/types/primitive/Generic/AccountId'
import { Tuple, Option } from '@polkadot/types/codec'
import Identity from '../identity/Identity'
import Attestation from './Attestation'
import AttestationUtils from './Attestation.utils'
import CType from '../ctype/CType'
import ICType from '../types/CType'
import RequestForAttestation from '../requestforattestation/RequestForAttestation'
import Claim from '../claim/Claim'
import { CompressedAttestation } from '../types/Attestation'
import CTypeUtils from '../ctype/CTypeUtils'

jest.mock('../blockchainApiConnection/BlockchainApiConnection')

describe('Attestation', () => {
  const identityAlice = Identity.buildFromURI('//Alice')
  const identityBob = Identity.buildFromURI('//Bob')

  const Blockchain = require('../blockchain/Blockchain').default

  const rawCType: ICType['schema'] = {
    $id: 'http://example.com/ctype-1',
    $schema: 'http://kilt-protocol.org/draft-01/ctype#',
    properties: {
      name: { type: 'string' },
    },
    type: 'object',
  }

  const fromRawCType: ICType = {
    schema: rawCType,
    owner: identityAlice.address,
    hash: CTypeUtils.getHashForSchema(rawCType),
  }

  const testCType: CType = CType.fromCType(fromRawCType)

  const testcontents = {}
  const testClaim = Claim.fromCTypeAndClaimContents(
    testCType,
    testcontents,
    identityBob.address
  )

  const requestForAttestation: RequestForAttestation = RequestForAttestation.fromClaimAndIdentity(
    testClaim,
    identityBob,
    [],
    null
  )

  it('stores attestation', async () => {
    Blockchain.api.query.attestation.attestations = jest.fn(() => {
      const tuple = new Option(
        Tuple,
        new Tuple(
          [Data, AccountId, Text, Bool],
          [testCType.hash, identityAlice.address, undefined, false]
        )
      )
      return Promise.resolve(tuple)
    })

    const attestation: Attestation = Attestation.fromRequestAndPublicIdentity(
      requestForAttestation,
      identityAlice
    )
    expect(await attestation.verify()).toBeTruthy()
  })

  it('verify attestations not on chain', async () => {
    Blockchain.api.query.attestation.attestations = jest.fn(() => {
      return Promise.resolve(new Option(Tuple))
    })

    const attestation: Attestation = Attestation.fromAttestation({
      claimHash: requestForAttestation.rootHash,
      cTypeHash: testCType.hash,
      delegationId: null,
      owner: identityAlice.address,
      revoked: false,
    })
    expect(await attestation.verify()).toBeFalsy()
  })

  it('verify attestation revoked', async () => {
    Blockchain.api.query.attestation.attestations = jest.fn(() => {
      return Promise.resolve(
        new Option(
          Tuple,
          new Tuple(
            // Attestations: claim-hash -> (ctype-hash, account, delegation-id?, revoked)
            [Data, AccountId, Text, Bool],
            [testCType.hash, identityAlice.address, undefined, true]
          )
        )
      )
    })

    const attestation: Attestation = Attestation.fromRequestAndPublicIdentity(
      requestForAttestation,
      identityAlice
    )
    expect(await attestation.verify()).toBeFalsy()
  })

  it('compresses and decompresses the attestation object', () => {
    const attestation = Attestation.fromRequestAndPublicIdentity(
      requestForAttestation,
      identityAlice
    )

    const compressedAttestation: CompressedAttestation = [
      attestation.claimHash,
      attestation.cTypeHash,
      attestation.owner,
      attestation.revoked,
      attestation.delegationId,
    ]

    expect(AttestationUtils.compress(attestation)).toEqual(
      compressedAttestation
    )

    expect(AttestationUtils.decompress(compressedAttestation)).toEqual(
      attestation
    )

    expect(Attestation.decompress(compressedAttestation)).toEqual(attestation)

    expect(attestation.compress()).toEqual(compressedAttestation)
  })

  it('Negative test for compresses and decompresses the attestation object', () => {
    const attestation = Attestation.fromRequestAndPublicIdentity(
      requestForAttestation,
      identityAlice
    )

    const compressedAttestation: CompressedAttestation = [
      attestation.claimHash,
      attestation.cTypeHash,
      attestation.owner,
      attestation.revoked,
      attestation.delegationId,
    ]
    compressedAttestation.pop()
    delete attestation.claimHash

    expect(() => {
      AttestationUtils.decompress(compressedAttestation)
    }).toThrow()

    expect(() => {
      Attestation.decompress(compressedAttestation)
    }).toThrow()
    expect(() => {
      attestation.compress()
    }).toThrow()
    expect(() => {
      AttestationUtils.compress(attestation)
    }).toThrow()
  it('should throw error on faulty constructor input', () => {
    const { cTypeHash, claimHash } = {
      cTypeHash:
        '0xa8c5bdb22aaea3fceb5467d37169cbe49c71f226233037537e70a32a032304ff',
      claimHash:
        '0x21a3448ccf10f6568d8cd9a08af689c220d842b893a40344d010e398ab74e557',
    }

    const everything = {
      claimHash,
      cTypeHash,
      owner: identityAlice.address,
    } as IAttestation

    const noClaimHash = {
      claimHash: '',
      cTypeHash,
      owner: identityAlice.address,
    } as IAttestation

    const noCTypeHash = {
      claimHash,
      cTypeHash: '',
      owner: identityAlice.address,
    } as IAttestation

    const noOwner = {
      claimHash,
      cTypeHash,
      owner: '',
    } as IAttestation

    const nothing = {
      claimHash: '',
      cTypeHash: '',
      owner: '',
    } as IAttestation

    const everythingExceptRequired = {
      claimHash: '',
      cTypeHash: '',
      owner: '',
      revoked: false,
      delegationId: null,
    } as IAttestation

    const malformedClaimHash = {
      claimHash: claimHash.slice(0, 20) + claimHash.slice(21),
      cTypeHash,
      owner: identityAlice.address,
      revoked: false,
      delegationId: null,
    } as IAttestation

    const malformedCTypeHash = {
      claimHash,
      cTypeHash: cTypeHash.slice(0, 20) + cTypeHash.slice(21),
      owner: identityAlice.address,
      revoked: false,
      delegationId: null,
    } as IAttestation

    expect(() =>
      // eslint-disable-next-line dot-notation
      Attestation['constructorInputCheck'](noClaimHash)
    ).toThrow()

    expect(() =>
      // eslint-disable-next-line dot-notation
      Attestation['constructorInputCheck'](noCTypeHash)
    ).toThrow()

    expect(() =>
      // eslint-disable-next-line dot-notation
      Attestation['constructorInputCheck'](noOwner)
    ).toThrow()

    expect(() =>
      // eslint-disable-next-line dot-notation
      Attestation['constructorInputCheck'](nothing)
    ).toThrow()

    expect(() =>
      // eslint-disable-next-line dot-notation
      Attestation['constructorInputCheck'](everythingExceptRequired)
    ).toThrow()

    expect(() =>
      // eslint-disable-next-line dot-notation
      Attestation['constructorInputCheck'](everything)
    ).not.toThrow()

    expect(() =>
      // eslint-disable-next-line dot-notation
      Attestation['constructorInputCheck'](malformedClaimHash)
    ).toThrow()

    expect(() =>
      // eslint-disable-next-line dot-notation
      Attestation['constructorInputCheck'](malformedCTypeHash)
    ).toThrow()
  })
})
