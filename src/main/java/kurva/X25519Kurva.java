package kurva;

import org.bouncycastle.math.ec.rfc7748.X25519;

import java.security.SecureRandom;

public class X25519Kurva implements Kurva {
    private byte[] privateKey = new byte[32];
    private byte[] publicKey = new byte[32];

    @Override
    public void create() {
        X25519.generatePrivateKey(new SecureRandom(), privateKey);
        X25519.generatePublicKey(privateKey, 0, publicKey, 0);
    }

    @Override
    public void fromPrivateKey(byte[] priv) {
        System.arraycopy(priv, 0, privateKey, 0, 32);
        X25519.generatePublicKey(privateKey, 0, publicKey, 0);
    }

    @Override
    public byte[] keyAgreement(byte[] pub) {
        byte[] secret = new byte[32];
        X25519.calculateAgreement(privateKey, 0, pub, 0, secret, 0);
        return secret;
    }

    @Override
    public byte[] getPublicKey() {
        return publicKey;
    }

    @Override
    public byte[] getPrivateKey() {
        return privateKey;
    }

}
