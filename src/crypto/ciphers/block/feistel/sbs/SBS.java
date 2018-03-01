/*
 * This code was written for an assignment for concept demonstration purposes:
 *  caution required
 *
 * The MIT License
 *
 * Copyright 2014 Victor de Lima Soares.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package crypto.ciphers.block.feistel.sbs;

import crypto.ciphers.block.feistel.FeistelCipher;
import crypto.util.BitBuffer;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * SBS is a symmetric block cipher based on Feistel structure.
 *
 * <p>
 * It encrypts blocks of 64 bits with a 56 bits key, returning block with 64
 * bits.</p>
 * <p>
 * Cleartext (64) + Key(56) = Ciphertext
 * </p>
 *
 * @author Victor de Lima Soares
 * @version 1.0
 */
public class SBS extends FeistelCipher {

    public static final int N_ROUNDS = 12;
    public static final int BLOCK_SIZE = 64;
    public static final int KEY_SIZE = 64;

    public static enum Modes {

        CBC
    };

    public SBS() {
        super(N_ROUNDS, BLOCK_SIZE);
    }

    @Override
    protected void initialPermutation(BitBuffer cipherText) {
        // SBSPermutation.IP.permute(cipherText);
    }

    @Override
    protected BitBuffer getRoundKey(BitBuffer keyBuffer, int round) {
        keyBuffer.shiftCyclicalLeft(1, KEY_SIZE);
        BitBuffer roundKey = (BitBuffer) keyBuffer.clone();
        return  roundKey;

    }

    @Override
    protected BitBuffer getRoundKeyDescryption(BitBuffer keyBuffer, int round) {
        if (round == 0) {
            for (int i = 0 ; i <= N_ROUNDS; i++) {
                keyBuffer.shiftCyclicalLeft(1, KEY_SIZE);
            }

        }
        keyBuffer.shiftCyclicalRight(1, KEY_SIZE);
        BitBuffer roundKey = (BitBuffer) keyBuffer.clone();
        return  roundKey;
    }

    @Override
    protected BitBuffer fFunction(final BitBuffer right, final BitBuffer roundKey
    ) {
        BitBuffer fBuffer = (BitBuffer) right.clone();
        fBuffer.matrixFlipHorizontal();
        fBuffer.matrixFlipVertical();
        BitBuffer sBuffer = new BitBuffer(BLOCK_SIZE / 2);
        for (int i = 0; i < SBoxes.getNSboxes(); i++) {
            try (BitBuffer sboxBits = fBuffer.get(i * SBox.INPUT_SIZE, i * SBox.INPUT_SIZE + SBox.INPUT_SIZE)) {
                SBoxes.get(i).replace(sboxBits);
                sBuffer.overwrite(i * SBox.OUTPUT_SIZE, sboxBits);
            }
        }
        sBuffer.xor(roundKey);
        sBuffer.shiftCyclicalLeft(3, sBuffer.length());
        sBuffer.xor(roundKey);
        sBuffer.twoByteSwap();
        sBuffer.xor(roundKey);
        return sBuffer;
    }

    @Override
    protected void finalPermutation(BitBuffer cipherText) {
        // SBSPermutation.inverseIP.permute(cipherText);
    }

    /**
     * Generates a byte array containing the key extracted from a MD5 hash for
     * the password.
     *
     * @since 1.0
     * @param password Input for the hash function.
     * @return Generated key.
     * @throws NoSuchAlgorithmException
     * <ul>
     * <li>If it can not find the "MD5" algorithm.</li>
     * </ul>
     */
    public static byte[] genkey(byte[] password) throws NoSuchAlgorithmException {

        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
        messageDigest.update(password, 0, password.length);

        byte buffer[] = new byte[8];

        System.arraycopy(messageDigest.digest(), 0, buffer, 0, 8);

        return buffer;
    }

    /**
     * Generates a byte array containing the key extracted from a MD5 hash for a
     * random number.
     *
     * @since 1.0
     * @return Generated key.
     * @throws NoSuchAlgorithmException
     * <ul>
     * <li>If it can not find the "MD5" algorithm.</li>
     * </ul>
     */
    public static byte[] genkey() throws NoSuchAlgorithmException {

        byte[] password = new byte[8];
        (new SecureRandom()).nextBytes(password);
        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
        messageDigest.update(password, 0, password.length);

        byte buffer[] = new byte[8];

        System.arraycopy(messageDigest.digest(), 0, buffer, 0, 8);
        BitBuffer.clearKeyBuffer(password);
        return buffer;
    }

    /**
     * Generates a byte array containing the key extracted from a MD5 hash for a
     * random number.
     *
     * <p>
     * If the first byte is non positive and the argument is set to true, the
     * first byte will be inverted. (This function makes easier to implement
     * functionalities with BigIntegers).
     * </p>
     *
     * @since 1.0
     * @return Generated key.
     * @throws NoSuchAlgorithmException
     * <ul>
     * <li>If it can not find the "MD5" algorithm.</li>
     * </ul>
     */
    public static byte[] genkey(boolean firstPositive) throws NoSuchAlgorithmException {

        byte[] buffer = genkey();

        if (firstPositive && buffer[0] <= 0) {
            buffer[0] = (byte) (-buffer[0] + 1);
        }

        return buffer;
    }
}
