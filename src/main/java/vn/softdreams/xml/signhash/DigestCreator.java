package vn.softdreams.xml.signhash;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.MessageDigest;
import java.security.Security;

/**
 * Created by chen on 7/24/17.
 */
public class DigestCreator {
    public static byte[] digest(byte[] data, DigestAlgorithm algo, boolean withInfo) throws Exception {
        return withInfo ? digestWithInfo(data, algo) : digest(data, algo);
    }

    public static byte[] digest(byte[] data, DigestAlgorithm algo) throws Exception {
        MessageDigest md = MessageDigest.getInstance(algo.getName());
        md.update(data);
        return md.digest();
    }

    public static byte[] digestWithInfo(byte[] data, DigestAlgorithm algo) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        MessageDigest messageDigest = MessageDigest.getInstance(algo.getName(), "BC");
        messageDigest.update(data);
        byte[] digest = messageDigest.digest();
        ASN1ObjectIdentifier oidObject = new ASN1ObjectIdentifier(algo.getOid());

        AlgorithmIdentifier identifier = new AlgorithmIdentifier(oidObject, null);
        DigestInfo di = new DigestInfo(identifier, digest);
        return di.getEncoded();
    }
}
