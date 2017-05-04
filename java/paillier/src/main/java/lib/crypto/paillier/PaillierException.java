/*
 * Copyright 2010-2017 Anirban Basu

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */

package lib.crypto.paillier;

import java.io.Serializable;

/**
 * Exceptions of this class are thrown by the Paillier cryptosystem. While
 * any message can be used to describe the reason for the exception, the class
 * also has some predefined messages that describe the common runtime problems
 * of the Paillier cryptosystem.
 * 
 * @author Anirban Basu
 *
 */
public class PaillierException extends RuntimeException implements Serializable {
	private static final long serialVersionUID = 1L;
	
	/**
	 * Indicates that the current instance of the cryptosystem cannot decrypt because it has not been initialised with a private key."
	 */
	public static final String TYPE_CRYPTOSYSTEM_CANNOT_DECRYPT = "This instance of the cryptosystem cannot decrypt as it does not have a private key.";
	
	/**
	 * Indicates that the modulus bit size is too low.
	 */
	public static final String TYPE_LOW_MODULUS_BIT_SIZE = "Modulus bit size must be at least: ";
	
	/**
	 * Indicates that the modulus bit size is too big.
	 */
	public static final String TYPE_HIGH_MODULUS_BIT_SIZE = "Modulus bit size must be at most: ";
	
	/**
	 * Indicates that the modulus bit size is odd. We need an even bit length modulus.
	 */
	public static final String TYPE_LOW_MODULUS_BIT_SIZE_ODD = "Modulus bit size should be even: ";
	
	/**
	 * Indicates that the plaintext is not in Z_n. However, if the cryptosystem accepts negative
	 * plaintexts, then the acceptable range of plaintext is from -n/2 to n/2. Any number more than
	 * n/2 will be treated as negative.
	 */
	public static final String TYPE_PLAINTEXT_NOT_IN_ZN = "Plaintext is not in Z_n: ";
	/**
	 * Indicates that the plaintext multiplicand is not in Z_n. However, if the cryptosystem accepts negative
	 * plaintexts, then the acceptable range of plaintext is from -n/2 to n/2. Any number more than
	 * n/2 will be treated as negative.
	 */
	public static final String TYPE_MULTIPLICAND_NOT_IN_ZN = "Plaintext multiplicand is not in Z_n: ";
	/**
	 * Indicates that the random number r in the encryption function is not in Z*_n.
	 */
	public static final String TYPE_RANDOM_NOT_IN_ZSTARN = "Random is not in Z*_n: ";
	/**
	 * Indicates that the ciphertext is not in Z*_{n^2}.
	 */
	public static final String TYPE_CIPHERTEXT_NOT_IN_ZSTARNSPLUSONE = "Ciphertext is not in Z*_{n^2}: ";
	/**
	 * Indicates that the plaintext is negative but the cryptosytem does not support it.
	 */
	public static final String TYPE_CRYPTOSYSTEM_NO_NEGATIVE = "No negative numbers are supported by this cryptosystem: ";

	
	public PaillierException() {
		super();
	}
	
	public PaillierException(String message) {
		super(message);
	}
	
	/**
	 * The error message is chosen from one of the specified error message types in this class,
	 *  followed by the Number argument which the error message is attributed to, if relevant.
	 * 
	 * @param message
	 * @param i
	 */
	public PaillierException(String message, Number i) {
		super(message + i.toString());
	}
	
}
