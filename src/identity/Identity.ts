import SubmittableExtrinsic from '@polkadot/api/promise/SubmittableExtrinsic'
/**
 * @module Identity
 */
import pair from '@polkadot/keyring/pair'
import { KeyringPair } from '@polkadot/keyring/types'
import generate from '@polkadot/util-crypto/mnemonic/generate'
import toSeed from '@polkadot/util-crypto/mnemonic/toSeed'
import validate from '@polkadot/util-crypto/mnemonic/validate'
import * as stringUtil from '@polkadot/util/string'
import * as u8aUtil from '@polkadot/util/u8a'
import padEnd from 'lodash/padEnd'
// see node_modules/@polkadot/util-crypto/nacl/keypair/fromSeed.js
// as util-crypto is providing a wrapper only for signing keypair
// and not for box keypair, we use TweetNaCl directly
import nacl, { BoxKeyPair, SignKeyPair } from 'tweetnacl'
import Crypto from '../crypto'
import {
  CryptoInput,
  EncryptedAsymmetric,
  EncryptedAsymmetricString,
} from '../crypto/Crypto'
import PublicIdentity from './PublicIdentity'

type BoxPublicKey =
  | PublicIdentity['boxPublicKeyAsHex']
  | Identity['boxKeyPair']['publicKey']

export default class Identity extends PublicIdentity {
  public static buildFromMnemonic(phraseArg?: string) {
    let phrase = phraseArg
    if (phrase) {
      if (phrase.trim().split(/\s+/g).length < 12) {
        // https://www.npmjs.com/package/bip39
        throw Error(`Phrase '${phrase}' too long or malformed`)
      }
    } else {
      phrase = generate()
    }

    if (!validate(phrase)) {
      throw Error(`Invalid phrase '${phrase}'`)
    }

    const seed = toSeed(phrase)
    return new Identity(seed, phrase)
  }

  public static buildFromSeedString(seedArg: string) {
    const padded = padEnd(seedArg, 32, ' ')
    const asU8a = stringUtil.stringToU8a(padded)
    return new Identity(asU8a)
  }

  private static ADDITIONAL_ENTROPY_FOR_HASHING = new Uint8Array([1, 2, 3])

  // fromSeed is hashing its seed, therefore an independent secret key should be considered as derived
  private static createSignKeyPair(seed: Uint8Array) {
    return nacl.sign.keyPair.fromSeed(seed)
  }

  // As fromSeed() is not implemented here we do our own hashing in order to prohibit inferring the original seed from a secret key
  // To be sure that we don't generate the same hash by accidentally using the same hash algorithm we do some padding
  private static createBoxKeyPair(seed: Uint8Array) {
    const paddedSeed = new Uint8Array(
      seed.length + Identity.ADDITIONAL_ENTROPY_FOR_HASHING.length
    )
    paddedSeed.set(seed)
    paddedSeed.set(Identity.ADDITIONAL_ENTROPY_FOR_HASHING, seed.length)

    const hash = Crypto.hash(paddedSeed)
    return nacl.box.keyPair.fromSecretKey(hash)
  }

  public readonly phrase?: string
  public readonly seed: Uint8Array
  public readonly seedAsHex: string
  public readonly signPublicKeyAsHex: string

  private readonly signKeyPair: SignKeyPair
  private readonly signKeyringPair: KeyringPair
  private readonly boxKeyPair: BoxKeyPair

  private constructor(seed: Uint8Array, phrase?: string) {
    // NB: use different secret keys for each key pair in order to avoid
    // compromising both key pairs at the same time if one key becomes public
    // Maybe use BIP32 and BIP44
    const signKeyPair = Identity.createSignKeyPair(seed)
    const signPublicKeyAsHex = u8aUtil.u8aToHex(signKeyPair.publicKey)
    const signKeyringPair: KeyringPair = pair({
      publicKey: signKeyPair.publicKey,
      secretKey: signKeyPair.secretKey,
    })

    const seedAsHex = u8aUtil.u8aToHex(seed)
    const address = signKeyringPair.address()

    const boxKeyPair = Identity.createBoxKeyPair(seed)
    const boxPublicKeyAsHex = u8aUtil.u8aToHex(boxKeyPair.publicKey)

    super(address, boxPublicKeyAsHex)

    this.phrase = phrase
    this.seed = seed
    this.seedAsHex = seedAsHex

    this.signKeyPair = signKeyPair
    this.signKeyringPair = signKeyringPair
    this.signPublicKeyAsHex = signPublicKeyAsHex

    this.boxKeyPair = boxKeyPair
  }

  public sign(cryptoInput: CryptoInput) {
    return Crypto.sign(cryptoInput, this.signKeyPair.secretKey)
  }

  public signStr(cryptoInput: CryptoInput) {
    return Crypto.signStr(cryptoInput, this.signKeyPair.secretKey)
  }

  public encryptAsymmetricAsStr(
    cryptoInput: CryptoInput,
    boxPublicKey: BoxPublicKey
  ) {
    return Crypto.encryptAsymmetricAsStr(
      cryptoInput,
      boxPublicKey,
      this.boxKeyPair.secretKey
    )
  }

  public decryptAsymmetricAsStr(
    encrypted: EncryptedAsymmetric | EncryptedAsymmetricString,
    boxPublicKey: BoxPublicKey
  ) {
    return Crypto.decryptAsymmetricAsStr(
      encrypted,
      boxPublicKey,
      this.boxKeyPair.secretKey
    )
  }

  public encryptAsymmetric(input: CryptoInput, boxPublicKey: BoxPublicKey) {
    return Crypto.encryptAsymmetric(
      input,
      boxPublicKey,
      this.boxKeyPair.secretKey
    )
  }

  public decryptAsymmetric(
    encrypted: EncryptedAsymmetric | EncryptedAsymmetricString,
    boxPublicKey: BoxPublicKey
  ) {
    return Crypto.decryptAsymmetric(
      encrypted,
      boxPublicKey,
      this.boxKeyPair.secretKey
    )
  }

  public signSubmittableExtrinsic(
    submittableExtrinsic: SubmittableExtrinsic,
    nonceAsHex: string
  ): SubmittableExtrinsic {
    return submittableExtrinsic.sign(this.signKeyringPair, nonceAsHex)
  }
}
