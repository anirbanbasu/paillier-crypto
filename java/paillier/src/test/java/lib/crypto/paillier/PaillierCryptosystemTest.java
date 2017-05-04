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
import java.util.Random;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import lib.crypto.interfaces.AdditivelyHomomorphicCryptosystem;

/**
 * Unit test for PaillierCryptosystem
 */
public class PaillierCryptosystemTest  extends TestCase {
    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
    public PaillierCryptosystemTest(String testName)
    {
        super( testName );
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite()
    {
        return new TestSuite(PaillierCryptosystemTest.class);
    }

    /**
     * Cryptographic operations test
     */
    public void testCryptographicOperations()
    {
    	Random rnd = new Random();
    	AdditivelyHomomorphicCryptosystem paillier = new PaillierCryptosystem(1024);
		BigInteger p1 = BigInteger.valueOf(rnd.nextLong());
		BigInteger p2 = BigInteger.valueOf(rnd.nextLong());
		BigInteger p3 = BigInteger.valueOf(rnd.nextLong());
		BigInteger c1 = paillier.encrypt(p1);
		BigInteger c2 = paillier.encrypt(p2);
		BigInteger c3 = paillier.homomorphicAdd(c1, c2);
		BigInteger c4 = paillier.homomorphicMultiply(c1, p3);
		BigInteger d1 = paillier.decrypt(c3);
		BigInteger d2 = paillier.decrypt(c4);
		assertTrue(d1.equals(p1.add(p2)));
		assertTrue(d2.equals(p1.multiply(p3)));
    }
}
