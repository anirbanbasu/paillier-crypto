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
import java.security.SecureRandom;
import java.util.Random;

import lib.crypto.interfaces.AdditivelyHomomorphicCryptosystem;

/**
 * An implementation of the Paillier optimised (i.e., g=(1+n)) cryptosystem.
 * @author Anirban Basu
 *
 */

public class PaillierCryptosystem implements AdditivelyHomomorphicCryptosystem {
	/**
	 * Minimum bit length of the cryptosystem.
	 */
	public static final int MIN_N_BIT_LENGTH = 8;
	/**
	 * Maximum bit length of the cryptosystem. This upper bound is provided entirely for the sake of performance reasons.
	 */
	public static final int MAX_N_BIT_LENGTH = 8192;
	
	private Random random = new SecureRandom(BigInteger.valueOf(System.nanoTime()).toByteArray());
	private BigInteger n, halfN, nSquared, lambda, mu;
	private int bitSize;
	private boolean canDecrypt = false;
	
	/**
	 * Create an instance of the Paillier cryptosystem that cannot decrypt.
	 * 
	 * @param n
	 * @param bitSize
	 */
	public PaillierCryptosystem(BigInteger n, int bitSize) {
		this.n = n;
		this.halfN = n.divide(BigInteger.valueOf(2)); //used for accepting negative inputs
		this.nSquared = n.multiply(n);
		this.bitSize = bitSize;
	}
	
	/**
	 * Create an instance of the Paillier cryptosystem that cannot decrypt.
	 * 
	 * @param n
	 * @param bitSize
	 */
	public PaillierCryptosystem(PaillierPublicKey publicKey) {
		this.n = publicKey.getN();
		if(publicKey.halfN == null) {
			this.halfN = n.divide(BigInteger.valueOf(2)); //used for accepting negative inputs
		}
		else {
			this.halfN = publicKey.halfN;
		}
		if(publicKey.nSquared == null) {
			this.nSquared = n.multiply(n);
		}
		else {
			this.nSquared = publicKey.nSquared;
		}
		this.bitSize = publicKey.getBitSize();
	}
	
	/**
	 * Create an instance of the Paillier cryptosystem.
	 * 
	 * @param n
	 * @param lambda
	 * @param mu
	 * @param bitSize
	 */
	public PaillierCryptosystem(BigInteger n, BigInteger lambda, BigInteger mu, int bitSize) {
		this.n = n;
		this.halfN = n.divide(BigInteger.valueOf(2)); //used for accepting negative inputs
		this.nSquared = n.multiply(n);
		this.lambda = lambda;
		this.mu = mu;
		this.bitSize = bitSize;
		this.canDecrypt = true;
	}
	
	/**
	 * Create an instance of the Paillier cryptosystem.
	 * 
	 * @param n
	 * @param lambda
	 * @param mu
	 * @param bitSize
	 */
	public PaillierCryptosystem(PaillierPrivateKey privateKey) {
		this.n = privateKey.getN();
		if(privateKey.halfN == null) {
			this.halfN = n.divide(BigInteger.valueOf(2)); //used for accepting negative inputs
		}
		else {
			this.halfN = privateKey.halfN;
		}
		if(privateKey.nSquared == null) {
			this.nSquared = n.multiply(n);
		}
		else {
			this.nSquared = privateKey.nSquared;
		}
		this.lambda = privateKey.getLambda();
		this.mu = privateKey.getMu();
		this.bitSize = privateKey.getBitSize();
		this.canDecrypt = true;
	}
	
	/**
	 * Create an instance of the Paillier cryptosystem and auto-generate the keys.
	 * 
	 * @param bitSize
	 */
	public PaillierCryptosystem(int bitSize) throws PaillierException {
		this.bitSize = bitSize;
		generateKeys();
	}
	
	private void checkBitSize() throws PaillierException {
		if(this.bitSize<MIN_N_BIT_LENGTH) {
			throw new PaillierException(PaillierException.TYPE_LOW_MODULUS_BIT_SIZE, MIN_N_BIT_LENGTH);
		}
		if(this.bitSize>MAX_N_BIT_LENGTH) {
			throw new PaillierException(PaillierException.TYPE_HIGH_MODULUS_BIT_SIZE, MAX_N_BIT_LENGTH);
		}
		if(this.bitSize%2!=0) {
			throw new PaillierException(PaillierException.TYPE_LOW_MODULUS_BIT_SIZE_ODD, this.bitSize);
		}
	}
	
	protected void generateKeys() {
		BigInteger p, q = null;
		checkBitSize();
    	do {
    	//chose a random prime number of bitSize/2 and ensure that n's bit size is bitSize
    		p = BigInteger.probablePrime(bitSize/2, random);
    		do {
    			//keep doing until q is distinct from p
    			q = BigInteger.probablePrime(bitSize/2, random);
    		} while ((p.multiply(q)).gcd((p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE))).compareTo(BigInteger.ONE)!=0
    				|| q.compareTo(p)==0);
        	n = p.multiply(q);
    	} while (n.bitLength()!=bitSize); //ensure strict bitSize for n
    	
    	nSquared = n.multiply(n);
    	halfN = n.divide(BigInteger.valueOf(2)); //used for accepting negative inputs
    	//lambda = lcm(p-1, q-1) = (p-1)*(q-1)/gcd(p-1, q-1)
    	lambda = (((p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE)))).divide(
            (p.subtract(BigInteger.ONE)).gcd(q.subtract(BigInteger.ONE)));
    	//mu = (L((1 + n lambda) mod n^2))^{-1} mod n, where L(u) = (u-1)/n
    	mu = (((n.multiply(lambda).add(BigInteger.ONE)).subtract(BigInteger.ONE)).divide(n)).modInverse(n);
    	this.canDecrypt = true;
    }
	
	public PaillierPublicKey getPublicKey() {
		return new PaillierPublicKey(n,halfN,nSquared,bitSize);
	}
	
	public PaillierPrivateKey getPrivateKey() {
		if(canDecrypt) {
			return new PaillierPrivateKey(n,halfN,nSquared,bitSize,lambda,mu);
		}
		else {
			return null;
		}
	}
	
	public BigInteger encrypt(BigInteger input) throws PaillierException  {
		if(!isInZN(input)) {
			throw new PaillierException(PaillierException.TYPE_PLAINTEXT_NOT_IN_ZN, input);
		}
		BigInteger plaintext = handleNegative(input);
		BigInteger r = randomInZStarN();
		return (((n.multiply(plaintext).add(BigInteger.ONE)).multiply(r.modPow(n, nSquared)))).mod(nSquared);
	}
	
	public BigInteger homomorphicAdd(BigInteger ciphertext1, BigInteger ciphertext2) throws PaillierException {
    	if (!isInZStarNSquared(ciphertext1))
        {
        	throw new PaillierException(PaillierException.TYPE_CIPHERTEXT_NOT_IN_ZSTARNSPLUSONE, ciphertext1);
        }
        if (!isInZStarNSquared(ciphertext2))
        {
        	throw new PaillierException(PaillierException.TYPE_CIPHERTEXT_NOT_IN_ZSTARNSPLUSONE, ciphertext2);
        }
        
        return ((ciphertext1.multiply(ciphertext2))).mod(nSquared);
                
    }
	
	public BigInteger decrypt(BigInteger ciphertext) throws PaillierException {
		if(!this.canDecrypt) {
			throw new PaillierException(PaillierException.TYPE_CRYPTOSYSTEM_CANNOT_DECRYPT);
		}
	    if (!isInZStarNSquared(ciphertext))
	    {
	        throw new PaillierException(PaillierException.TYPE_CIPHERTEXT_NOT_IN_ZSTARNSPLUSONE,ciphertext);
	    }
        // m = L(c^lambda mod n^2) * mu mod n, where L(u) = (u-1)/n
        return handleNegative(((((ciphertext.modPow(lambda, nSquared)).subtract(BigInteger.ONE)).divide(n)).multiply(mu)).mod(n));
    }
	
	public BigInteger homomorphicMultiply(BigInteger ciphertext, BigInteger multiplicand) throws PaillierException {
    	
    	if (!isInZStarNSquared(ciphertext))
        {
        	throw new PaillierException(PaillierException.TYPE_CIPHERTEXT_NOT_IN_ZSTARNSPLUSONE, ciphertext);
        }
        if (!isInZN(multiplicand))
        {
        	throw new PaillierException(PaillierException.TYPE_MULTIPLICAND_NOT_IN_ZN, multiplicand);
        }
    	BigInteger plaintext = handleNegative(multiplicand);
        return (ciphertext.modPow(plaintext, nSquared));
                
    }
	
	protected BigInteger handleNegative(BigInteger input) {
    	if(input.compareTo(BigInteger.ZERO)<0 && input.abs().compareTo(halfN)<0) {
    		//a negative plaintext input, convert to modular additive inverse
    		return n.add(input);
    	}
    	else if (input.compareTo(halfN) >=0) {
    		//perhaps decrypted ciphertext, convert to additive inverse
    		return input.subtract(n);
    	}
    	else {
    		//otherwise, nothing to change
    		return input;
    	}
    }
	
	protected BigInteger randomInZStarN() {
    	BigInteger r;
    	do
        {
            r = new BigInteger(bitSize, random);
          //FIXME: This method is preferred to the BigInteger constructor but it is slower, see Javadoc for BigInteger
    	  //r = BigInteger.probablePrime(bitSize, random);
        } while (!isInZStarN(r));
    	return r;
    }
	
	private boolean isInZStarN(BigInteger input) {
    	return !(input.compareTo(BigInteger.ZERO) <= 0 || 
    			input.compareTo(n) >= 0 || 
    			input.gcd(n).compareTo(BigInteger.ONE)!=0);
    }
	
	private boolean isInZN(BigInteger input) {
		return (input.abs().compareTo(halfN)<0);
    }
	
	private boolean isInZStarNSquared(BigInteger input) {
    	return !(input.compareTo(BigInteger.ZERO) <= 0 || 
    			input.compareTo(nSquared) >= 0 || 
    			input.gcd(nSquared).compareTo(BigInteger.ONE)!=0);
    }

	public int getBitSize() {
		return bitSize;
	}
	
	/**
	 * Shows a string representation of the cryptosystem showing the keys in the format
	 * 
	 * Paillier-[N] CS {n=[pubK]; lambda=[lambda]; mu=[mu]}
	 * 
	 * where [N] signifies the bit length of the cryptosystem. The presence of lambda and mu
	 * implies that the cryptosystem has a private key and is able to decrypt. 
	 */
	public String description() {
		return "Paillier-" + bitSize + " CS {n=" + n + "; lambda=" + lambda + "; mu=" + mu +  "}";
	}
	
	/**
	 * Shows a string representation of the cryptosystem showing the keys in the format
	 * 
	 * Paillier-[N] cryptosystem
	 * 
	 * where [N] signifies the bit length of the cryptosystem. 
	 */
	public String toString() {
		return "Paillier-" + bitSize + " cryptosystem";
	}
}
