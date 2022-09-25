package kurva;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;

import javax.crypto.KeyAgreement;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

public class BouncyKurva implements Kurva {
    public static final String ECDH = "ECDH";
    BouncyCastleProvider bc = new BouncyCastleProvider();
    X9ECParameters curveParams = CustomNamedCurves.getByName("curve25519");
    ECParameterSpec pSpec = new ECParameterSpec(curveParams.getCurve(), curveParams.getG(), curveParams.getN(), curveParams.getH(), curveParams.getSeed());

    private ECPrivateKey ecPrivateKey;
    private ECPublicKey ecPublicKey;

    @Override
    public void create() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(ECDH, bc);
        kpg.initialize(pSpec);
        KeyPair kp = kpg.generateKeyPair();
        ecPrivateKey = (ECPrivateKey) kp.getPrivate();
        ecPublicKey = (ECPublicKey) kp.getPublic();
    }

    @Override
    public void fromPrivateKey(byte[] priv) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("ECDH", bc);
        BigInteger d = new BigInteger(priv);
        ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(d, pSpec);
        ecPrivateKey = (ECPrivateKey) kf.generatePrivate(privateKeySpec);
        ECPoint q = new FixedPointCombMultiplier().multiply(pSpec.getG(), d);
        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(q, pSpec);
        ecPublicKey = (ECPublicKey) kf.generatePublic(pubKeySpec);
    }

    @Override
    public byte[] keyAgreement(byte[] pub) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH", bc);
        ka.init(ecPrivateKey);
        ka.doPhase(toPublicKey(pub), true);
        return ka.generateSecret();
    }

    @Override
    public byte[] getPublicKey() {
        return ecPublicKey.getQ().getEncoded(true);
    }

    @Override
    public byte[] getPrivateKey() {
        return ecPrivateKey.getD().toByteArray();
    }

    private PublicKey toPublicKey(final byte[] data) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        ECPublicKeySpec pubKey = new ECPublicKeySpec(pSpec.getCurve().decodePoint(data), pSpec);
        KeyFactory kf = KeyFactory.getInstance("ECDH", bc);
        return kf.generatePublic(pubKey);
    }

}
