package org.github.chids.bcpgp;

import static org.github.chids.bcpgp.KeyUtil.findPublicKey;
import static org.github.chids.bcpgp.KeyUtil.findPublicKeyFromPrivate;
import static org.github.chids.bcpgp.KeyUtil.findSecretKey;
import static org.github.chids.bcpgp.PGPTest.findFile;
import static org.junit.Assert.assertTrue;

import java.io.IOException;

import org.bouncycastle.openpgp.PGPException;
import org.junit.Test;

public class KeyUtilTest {

    @Test
    public void testFindPublicKeyFromPrivate() throws IOException, PGPException {
        assertTrue(findPublicKeyFromPrivate(findFile(PGPTest.PRIVATE_KEY_FILE)).isEncryptionKey());
    }

    @Test
    public void testFindPublicKey() throws IOException, PGPException {
        assertTrue(findPublicKey(findFile(PGPTest.PUBLIC_KEY_FILE)).isEncryptionKey());
    }

    @Test
    public void testFindPrivateKey() throws IOException, PGPException {
        assertTrue(findSecretKey(findFile(PGPTest.PRIVATE_KEY_FILE)).isSigningKey());
    }
}
