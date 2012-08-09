package org.github.chids.bcpgp;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.io.InputStream;
import java.util.UUID;

import org.bouncycastle.openpgp.PGPException;
import org.junit.Test;

public class PGPTest {

    public static final String PASSPHRASE = "unittest";
    public static final String PUBLIC_KEY_FILE = "mock.key.public";
    public static final String PRIVATE_KEY_FILE = "mock.key.private";

    @Test
    public void encryptAndDecryptUsingMockKey() throws IOException, PGPException {
        final String secret = UUID.randomUUID().toString();
        final byte[] encrypted = PGP.encrypt(
                secret.getBytes(),
                KeyUtil.findPublicKey(findFile(PUBLIC_KEY_FILE)));
        final byte[] decrypted = PGP.decrypt(
                encrypted,
                findFile(PRIVATE_KEY_FILE),
                PASSPHRASE);
        assertEquals(secret, new String(decrypted));
    }

    @Test
    public void encryptAndDecryptWithMultipleRecipientsUsingMockKey() throws IOException, PGPException {
        final String secret = UUID.randomUUID().toString();
        final byte[] encrypted = PGP.encrypt(
                secret.getBytes(),
                KeyUtil.findPublicKey(findFile(PUBLIC_KEY_FILE)),
                KeyUtil.findPublicKeyFromPrivate(findFile(PRIVATE_KEY_FILE)));
        final byte[] decrypted = PGP.decrypt(
                encrypted,
                findFile(PRIVATE_KEY_FILE),
                PASSPHRASE);
        assertEquals(secret, new String(decrypted));
    }

    public static InputStream findFile(final String file) {
        return PGPTest.class.getClassLoader().getResourceAsStream(file);
    }
}