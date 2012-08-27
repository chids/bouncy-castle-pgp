package org.github.chids.bcpgp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.io.Streams;

/**
 * This code is a result of reworking and cleaning up example and test code from the Bouncy Castle projects source.
 */
public class PGP
{
    public static final BouncyCastleProvider provider = new BouncyCastleProvider();

    static {
        Security.addProvider(provider);
    }

    public static byte[] decrypt(
                                 final byte[] data,
                                 final InputStream privateKey,
                                 final String passphrase)
            throws IOException, PGPException
    {
        final PGPLiteralData message = asLiteral(data, privateKey, passphrase);
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(message.getInputStream(), out);
        return out.toByteArray();
    }

    public static byte[] encrypt(
                                 final byte[] secret,
                                 final PGPPublicKey... keys)
            throws IOException, PGPException
    {
        final ByteArrayInputStream in = new ByteArrayInputStream(secret);
        final ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        final PGPLiteralDataGenerator literal = new PGPLiteralDataGenerator();
        final PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(CompressionAlgorithmTags.UNCOMPRESSED);
        final OutputStream pOut = literal.open(
                comData.open(bOut),
                PGPLiteralData.BINARY,
                "filename",
                in.available(),
                new Date());
        Streams.pipeAll(in, pOut);
        comData.close();
        final byte[] bytes = bOut.toByteArray();
        final PGPEncryptedDataGenerator generator = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.CAST5)
                        .setWithIntegrityPacket(true)
                        .setSecureRandom(new SecureRandom())
                        .setProvider(provider));
        for(final PGPPublicKey key : keys) {
            generator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(key).setProvider(provider));
        }
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final ArmoredOutputStream armor = new ArmoredOutputStream(out);
        final OutputStream cOut = generator.open(armor, bytes.length);
        cOut.write(bytes);
        cOut.close();
        armor.close();
        return out.toByteArray();
    }

    @SuppressWarnings("unchecked")
    private static Iterator<PGPPublicKeyEncryptedData> getEncryptedObjects(final byte[] data) throws IOException {
        final PGPObjectFactory factory = new PGPObjectFactory(PGPUtil.getDecoderStream(new ByteArrayInputStream(data)));
        final Object first = factory.nextObject();
        final Object list = (first instanceof PGPEncryptedDataList) ? first : factory.nextObject();
        return ((PGPEncryptedDataList)list).getEncryptedDataObjects();
    }

    public static byte[] signEncryptFile(
                                         final byte[] secret,
                                         final PGPSecretKey secretKey,
                                         final String password,
                                         final PGPPublicKey... publicKeys) throws PGPException, IOException,
            SignatureException {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final OutputStream armor = new ArmoredOutputStream(out);
        final PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.CAST5)
                        .setWithIntegrityPacket(true)
                        .setSecureRandom(new SecureRandom())
                        .setProvider(provider));
        for(final PGPPublicKey publicKey : publicKeys) {
            encryptedDataGenerator.addMethod(
                    new JcePublicKeyKeyEncryptionMethodGenerator(publicKey)
                            .setSecureRandom(new SecureRandom())
                            .setProvider(provider));
        }
        final OutputStream encryptedOut = encryptedDataGenerator.open(armor, new byte[4096]);
        final PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(
                CompressionAlgorithmTags.ZIP);
        final OutputStream compressedOut = compressedDataGenerator.open(encryptedOut, new byte[4096]);
        final PGPPrivateKey privateKey = secretKey.extractPrivateKey(
                new JcePBESecretKeyDecryptorBuilder()
                        .setProvider(provider)
                        .build(password.toCharArray()));
        final PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(
                secretKey.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1).setProvider(provider));
        signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);
        final Iterator<?> it = secretKey.getPublicKey().getUserIDs();
        if(it.hasNext()) {
            final PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
            spGen.setSignerUserID(false, (String)it.next());
            signatureGenerator.setHashedSubpackets(spGen.generate());
        }
        signatureGenerator.generateOnePassVersion(false).encode(compressedOut);
        final PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
        final OutputStream literalOut = literalDataGenerator.open(
                compressedOut,
                PGPLiteralData.BINARY,
                "filename",
                new Date(),
                new byte[4096]);
        final InputStream in = new ByteArrayInputStream(secret);
        final byte[] buf = new byte[4096];
        for(int len = 0; (len = in.read(buf)) > 0;) {
            literalOut.write(buf, 0, len);
            signatureGenerator.update(buf, 0, len);
        }
        in.close();
        literalDataGenerator.close();
        signatureGenerator.generate().encode(compressedOut);
        compressedDataGenerator.close();
        encryptedDataGenerator.close();
        armor.close();
        return out.toByteArray();
    }

    private static PGPLiteralData asLiteral(
                                            final byte[] data,
                                            final InputStream keyfile,
                                            final String passphrase) throws IOException, PGPException {
        PGPPrivateKey key = null;
        PGPPublicKeyEncryptedData encrypted = null;
        final PGPSecretKeyRingCollection keys = new PGPSecretKeyRingCollection(new ArmoredInputStream(keyfile));
        for(final Iterator<PGPPublicKeyEncryptedData> i = getEncryptedObjects(data); (key == null) && i.hasNext();) {
            encrypted = i.next();
            key = findSecretKey(keys, encrypted.getKeyID(), passphrase);
        }
        if(key == null) {
            throw new IllegalArgumentException("secret key for message not found.");
        }
        final InputStream stream = encrypted.getDataStream(
                new JcePublicKeyDataDecryptorFactoryBuilder()
                        .setProvider(provider)
                        .build(key));
        return asLiteral(stream);
    }

    private static PGPLiteralData asLiteral(final InputStream clear) throws IOException, PGPException {
        final PGPObjectFactory plainFact = new PGPObjectFactory(clear);
        final Object message = plainFact.nextObject();
        if(message instanceof PGPCompressedData) {
            final PGPCompressedData cData = (PGPCompressedData)message;
            final PGPObjectFactory pgpFact = new PGPObjectFactory(cData.getDataStream());
            // Find the first PGPLiteralData object
            Object object = null;
            for(int safety = 0; (safety++ < 1000) && !(object instanceof PGPLiteralData); object = pgpFact.nextObject()) {
                ;
            }
            return (PGPLiteralData)object;
        }
        else
            if(message instanceof PGPLiteralData) {
                return (PGPLiteralData)message;
            }
            else
                if(message instanceof PGPOnePassSignatureList) {
                    throw new PGPException("encrypted message contains a signed message - not literal data.");
                }
                else {
                    throw new PGPException("message is not a simple encrypted file - type unknown: "
                            + message.getClass().getName());
                }
    }

    private static PGPPrivateKey findSecretKey(
                                               final PGPSecretKeyRingCollection keys,
                                               final long id,
                                               final String passphrase) {
        try {
            final PGPSecretKey key = keys.getSecretKey(id);
            if(key != null) {
                return key.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder()
                        .setProvider(provider)
                        .build(passphrase.toCharArray()));
            }
        }
        catch(final Exception e) {
            // Don't print the passphrase but do print null if thats what it was
            final String passphraseMessage = (passphrase == null) ? "null" : "supplied";
            System.err.println("Unable to extract key " + id + " using " + passphraseMessage + " passphrase");
        }
        return null;
    }
}
