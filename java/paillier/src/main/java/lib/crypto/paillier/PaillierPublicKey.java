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

import lib.crypto.interfaces.PublicKey;

/**
 * The public key of the Paillier cryptosystem.
 * 
 * @author Anirban Basu
 *
 */
public class PaillierPublicKey implements PublicKey {
	public PaillierPublicKey() {}
	
	public PaillierPublicKey(BigInteger n, BigInteger halfN,
			BigInteger nSquared, int bitSize) {
		this.n = n;
		this.halfN = halfN;
		this.nSquared = nSquared;
		this.bitSize = bitSize;
	}
	
	private static final long serialVersionUID = 1L;
	protected BigInteger n = null, halfN = null, nSquared = null;
	protected int bitSize;
	public BigInteger getN() {
		return n;
	}
	public void setN(BigInteger n) {
		this.n = n;
	}
	public int getBitSize() {
		return bitSize;
	}
	public void setBitSize(int bitSize) {
		this.bitSize = bitSize;
	}
	
}
