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

import java.math.BigInteger;

import lib.crypto.interfaces.PrivateKey;

/**
 * A private key of the Paillier cryptosystem. Note that the private key is a
 * subclass of the public key.
 * 
 * @author Anirban Basu
 *
 */
public class PaillierPrivateKey extends PaillierPublicKey implements PrivateKey {
	public PaillierPrivateKey() {}
	
	public PaillierPrivateKey(BigInteger n, BigInteger halfN,
			BigInteger nSquared, int bitSize, BigInteger lambda, BigInteger mu) {
		super(n, halfN, nSquared, bitSize);
		this.lambda = lambda;
		this.mu = mu;
	}
	
	private static final long serialVersionUID = 1L;
	protected BigInteger lambda = null, mu = null;
	public BigInteger getLambda() {
		return lambda;
	}
	public void setLambda(BigInteger lambda) {
		this.lambda = lambda;
	}
	public BigInteger getMu() {
		return mu;
	}
	public void setMu(BigInteger mu) {
		this.mu = mu;
	}
}
