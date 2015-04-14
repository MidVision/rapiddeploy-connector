package com.midvision.rapiddeploy.connector;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collections;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * 
 * @author Mariano Prediletto
 * 
 */
public class JCEHelper {

    // Algorithms
    public static final String AES = "AES";
    public static final String ARCFOUR_RC4 = "ARCFOUR/RC4";
    public static final String BLOWFISH = "Blowfish";
    public static final String DES = "DES";
    public static final String DES_EDE = "DESede";
    public static final String ECIES = "ECIES";
    public static final String RC2 = "RC2";
    public static final String RC4 = "RC4";
    public static final String RC5 = "RC5";
    public static final String RSA = "RSA";
    public static final String DSA = "DSA";
    public static final String MD5 = "MD5";
    // Modes
    public static final String NONE = "NONE";
    public static final String CBC = "CBC";
    public static final String CFB = "CFB";
    public static final String ECB = "ECB";
    public static final String OFB = "OFB";
    public static final String PCBC = "PCBC";
    // Padding
    public static final String NO_PADDING = "NoPadding";
    public static final String ISO10126_PADDING = "ISO10126Padding";
    public static final String PKCS5_PADDING = "PKCS5Padding";
    public static final String SSL3_PADDING = "SSL3Padding";

    public static final String SHA_256 = "SHA-256";
    public static final String SHA256 = "SHA256";
    public static final String X509 = "X.509";
    private static final String WITH = "With";
    private static final String PKIX = "PKIX";

    /**
     * 
     * @param data
     * @param transformation
     *            "algorithm/mode/padding" or "algorithm"
     * @param key
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static byte[] encrypt(final byte[] data, final String transformation, final Key key)
    throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
    BadPaddingException {
        if (data != null) {
            final Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(data);
        }
        return null;
    }

    /**
     * 
     * @param data
     * @param transformation
     *            "algorithm/mode/padding" or "algorithm"
     * @param key
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static byte[] decrypt(final byte[] data, final String transformation, final Key key)
    throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
    BadPaddingException {
        if (data != null) {
            final Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(data);
        }
        return null;
    }

    /**
     * 
     * @param data
     * @param algorithm
     * @return
     * @throws NoSuchAlgorithmException
     * @throws IOException
     */
    public static byte[] createHashValue(final byte[] data, final String algorithm) throws NoSuchAlgorithmException,
    IOException {
        final MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
        messageDigest.reset();
        messageDigest.update(data);
        return messageDigest.digest();
    }

    /**
     * 
     * @param data
     * @param digestAlgo
     * @param publicKey
     * @param privateKey
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     * @throws IOException
     */
    public static byte[] createSignature(final byte[] data, final String digestAlgo, final PublicKey publicKey,
            final PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException,
            IOException {
        return createSignature(data, digestAlgo, publicKey.getAlgorithm(), privateKey);
    }

    /**
     * 
     * @param data
     * @param digestAlgo
     * @param algorithm
     * @param privateKey
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     * @throws IOException
     */
    public static byte[] createSignature(final byte[] data, final String digestAlgo, final String algorithm,
            final PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException,
            IOException {
        final Signature signature = Signature.getInstance(digestAlgo + WITH + algorithm);
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    /**
     * 
     * @param data
     * @param signedDigest
     * @param digestAlgo
     * @param publicKey
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     * @throws IOException
     */
    public static boolean verifySignature(final byte[] data, final byte[] signedDigest, final String digestAlgo,
            final PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException,
            IOException {
        final Signature signature = Signature.getInstance(digestAlgo + WITH + publicKey.getAlgorithm());
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signedDigest);
    }

    /**
     * 
     * @param bytes24
     * @return
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static Key create3DESKey(final byte[] bytes24) throws InvalidKeyException, NoSuchAlgorithmException,
    InvalidKeySpecException {
        final DESedeKeySpec keySpec = new DESedeKeySpec(bytes24);
        final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(DES_EDE);
        return keyFactory.generateSecret(keySpec);
    }

    /**
     * 
     * @param bits128or192or256
     * @return
     */
    public static Key createAESKey(final byte[] bits128or192or256) {
        return new SecretKeySpec(bits128or192or256, AES);
    }

    /**
     * 
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static KeyPair createRSAKeyPair() throws NoSuchAlgorithmException {
        return KeyPairGenerator.getInstance(RSA).generateKeyPair();
    }

    /**
     * 
     * @param is
     * @return
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public static PrivateKey loadPrivateKey(final InputStream is) throws IOException, GeneralSecurityException {
        return loadPrivateKey(loadStream(is));
    }

    /**
     * 
     * @param data
     * @return
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public static PrivateKey loadPrivateKey(final byte[] data) throws IOException, GeneralSecurityException {
        // openssl pkcs8 -topk8 -in personal-privkey.pem -outform DER -out
        // personal-privkey.der -nocrypt
        final KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        final KeySpec privSpec = new PKCS8EncodedKeySpec(data);
        return keyFactory.generatePrivate(privSpec);
    }

    /**
     * 
     * @param is
     * @return
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public static PublicKey loadPublicKey(final InputStream is) throws IOException, GeneralSecurityException {
        return loadPublicKey(loadStream(is));
    }

    /**
     * 
     * @param data
     * @return
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public static PublicKey loadPublicKey(final byte[] data) throws IOException, GeneralSecurityException {
        // openssl x509 -in personal-cert.x509.pem.crt -out personal-pubkey.pem
        // -pubkey
        final X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
        final KeyFactory kf = KeyFactory.getInstance(RSA);
        return kf.generatePublic(spec);
    }

    /**
     * 
     * @param is
     * @return
     * @throws CertificateException
     */
    public static X509Certificate loadX509Certificate(final InputStream is) throws CertificateException {
        final CertificateFactory certificateFactory = CertificateFactory.getInstance(X509);
        return (X509Certificate) certificateFactory.generateCertificate(is);
    }

    /**
     * 
     * @param certChain
     * @return
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws CertPathValidatorException
     */
    public static PKIXCertPathValidatorResult validateCertPath(final List<Certificate> certChain)
    throws CertificateException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
    CertPathValidatorException {
        // Instantiate a CertificateFactory for X.509
        final CertificateFactory cf = CertificateFactory.getInstance(X509);
        // Extract the certification path from the List of Certificates
        final CertPath cp = cf.generateCertPath(certChain);
        // Create CertPathValidator that implements the "PKIX" algorithm
        final CertPathValidator cpv = CertPathValidator.getInstance(PKIX);
        // Set the Trust anchor
        final TrustAnchor anchor = new TrustAnchor((X509Certificate) certChain.get(certChain.size() - 1), null);
        final PKIXParameters params = new PKIXParameters(Collections.singleton(anchor));
        params.setRevocationEnabled(false);
        // Validate and obtain results
        return (PKIXCertPathValidatorResult) cpv.validate(cp, params);
    }

    /**
     * 
     * @param obj
     * @param key
     * @return
     */
    public static SealedObject creatSealedObject(final Serializable obj, final Key key) {
        try {
            final Cipher c = Cipher.getInstance(RSA);
            c.init(Cipher.ENCRYPT_MODE, key);
            // do the sealing
            return new SealedObject(obj, c);

        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 
     * @param so
     * @param key
     * @return
     */
    public static Serializable restoreSealedObject(final SealedObject so, final Key key) {
        try {
            final Cipher c = Cipher.getInstance(RSA);
            c.init(Cipher.DECRYPT_MODE, key);
            return (Serializable) so.getObject(c);
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] loadStream(final InputStream is) throws IOException {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            int val = 0;
            while ((val = is.read()) != -1) {
                baos.write(val);
            }
        } finally {
            is.close();
        }
        return baos.toByteArray();
    }
}
