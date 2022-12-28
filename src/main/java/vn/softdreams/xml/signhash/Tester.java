package vn.softdreams.xml.signhash;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.crypto.Cipher;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class Tester {
    String inputXmlFileName = "xmlChuaKy.xml";
    String p12FileName = "test.p12";
    String p12FilePass = "easykey";

    private X509Certificate cert;
    private PrivateKey privateKey;
    private Certificate[] chain;

    private Document inputDoc;

    String signingTagId;
    String signingTagName;
    String namespacePrefix;

    final String OUTPUT_FOLDER = "C:\\Users\\User\\IdeaProjects\\xml-dsig-sign-hash\\DATA\\";

    public static void main(String[] args) {
        new Tester().doTest();
    }

    void initTest() throws Exception {
        configureForCyberBill();
        loadXml();
        loadP12(p12FileName, p12FilePass);
    }

    void configureForCyberBill() {
        signingTagId = "";
        signingTagName = "invoiceData";
        namespacePrefix = "";
    }

    void configureForSample() {
        signingTagId = "signingData";
        namespacePrefix = "";
        signingTagName = "catalog";
    }

    void doTest() {
        try {
            initTest();
            HashOperator hashOperator = new HashOperator(inputDoc, cert, signingTagId, signingTagName, namespacePrefix);
            HashOperator.HashResponse response = hashOperator.performDigest();
            String sessionId = response.getId();
            String digest = response.getHash();

            byte[] sig = signHashWithInfo(Base64.getDecoder().decode(digest), privateKey, hashOperator.getHashAlgo());
            String b64Signature = Base64.getEncoder().encodeToString(sig);

            Wrapper wrapper = new Wrapper();
            Document finalDoc = wrapper.wrapSignature(sessionId, b64Signature);
            String outputPath = OUTPUT_FOLDER + "signed_" + sessionId + ".xml";
            wrapper.write(finalDoc, outputPath, false);
            System.out.println("Sign process is done!");

            Validator validator = new Validator();
            boolean isValid = validator.verify(new FileInputStream(outputPath), signingTagName);
            System.out.println("Check signed document: " + isValid);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private InputStream getFileFromResource(String fileName) {
        ClassLoader classLoader = getClass().getClassLoader();
        return classLoader.getResourceAsStream(fileName);
    }

    private void loadXml() throws Exception {
        InputStream xmlIs = getFileFromResource(inputXmlFileName);
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        dbFactory.setNamespaceAware(true);
        dbFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();

        //Xử lý minimize xml file, loại bỏ khoảng trắng, xuống dòng
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(xmlIs));
        String line;
        StringBuilder sb = new StringBuilder();
        while ((line = bufferedReader.readLine()) != null) {
            sb.append(line.trim());
        }
        String minimizedXml = sb.toString();

        inputDoc = dBuilder.parse(new ByteArrayInputStream(minimizedXml.getBytes()));
        inputDoc.getDocumentElement().normalize();

        //Kiểm tra nếu thẻ cần ký chưa có Id (ReferenceId) thì thêm vào
        if (signingTagName == null) throw new Exception("SigningTagName must be defined");
        if (signingTagId == null) throw new Exception("SigningTagId must be defined");
//        NodeList nl = inputDoc.getElementsByTagName(signingTagName);
//        for (int i = 0; i < nl.getLength(); i++) {
//            Node node = nl.item(i);
//            if (node.getAttributes().getNamedItem("ID") == null) {
//                Element element = (Element) node;
//                element.setAttribute("ID", signingTagId);
//            }
//        }
    }

    private void loadP12(String p12FileName, String p12FilePass) throws Exception {
        InputStream fis = getFileFromResource(p12FileName);

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(fis, p12FilePass.toCharArray());
        String alias = keyStore.aliases().nextElement();
        this.privateKey = (PrivateKey) keyStore.getKey(alias, p12FilePass.toCharArray());
        this.chain = keyStore.getCertificateChain(alias);
        this.cert = (X509Certificate) keyStore.getCertificate(alias);
    }

    public byte[] signHash(byte[] hash, PrivateKey privateKey) throws Exception {
        Provider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", provider);
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return cipher.doFinal(hash);
    }

    public byte[] signHashWithInfo(byte[] hash, PrivateKey privateKey, DigestAlgorithm algo) throws Exception {
        Provider provider = new BouncyCastleProvider();
        Security.addProvider(provider);

        ASN1ObjectIdentifier oidObject = new ASN1ObjectIdentifier(algo.getOid());

        AlgorithmIdentifier identifier = new AlgorithmIdentifier(oidObject, null);
        DigestInfo di = new DigestInfo(identifier, hash);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", provider);
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return cipher.doFinal(di.getEncoded());
    }
}
