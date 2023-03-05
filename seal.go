/*
 * Copyright (c) 2022-2023 Zander Schwid & Co. LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package seal

import (
	"crypto"
	"crypto/cipher"
	"reflect"
)

/**
Seal interface
*/

type SealerOptions struct {

	Algorithm  string

	PublicKey  crypto.PublicKey

	PrivateKey crypto.PrivateKey  // optional

}

type SealerOption interface {
	Apply(*SealerOptions) error
}

type CipherOptions struct {

	Algorithm  string

	Block  cipher.Block

}

type CipherOption interface {
	Apply(*CipherOptions) error
}

type AsymmetricSealer interface {

	PublicKey()  crypto.PublicKey

	PrivateKey()  crypto.PrivateKey

	EncodePublicKey()  (string, error)

	EncodePrivateKey()  (string, error)

	Seal(plaintext []byte, recipient crypto.PublicKey)  (ciphertext []byte, err error)

	Open(ciphertext []byte, sender crypto.PublicKey)  (plaintext []byte, err error)

}

type AsymmetricSigner interface {

	PublicKey()  crypto.PublicKey

	PrivateKey()  crypto.PrivateKey

	EncodePublicKey()  (string, error)

	EncodePrivateKey()  (string, error)

	Sign(plaintext []byte)  (sign []byte, err error)

	Verify(plaintext, sign []byte)  (valid bool, err error)

}

type AuthenticatedCipher interface {

	Key() cipher.AEAD

	Encrypt(plaintext []byte) (ciphertext []byte, err error)

	Decrypt(ciphertext []byte) (plaintext []byte, err error)

}

var SealServiceClass = reflect.TypeOf((*SealService)(nil)).Elem()

type SealService interface {

	IssueSealer(algorithm string, bits int) (AsymmetricSealer, error)

	Sealer(options ...SealerOption) (AsymmetricSealer, error)

	IssueSigner(algorithm string, bits int) (AsymmetricSigner, error)

	Signer(options ...SealerOption) (AsymmetricSigner, error)

	AuthenticatedCipher(options ...CipherOption) (AuthenticatedCipher, error)

}



