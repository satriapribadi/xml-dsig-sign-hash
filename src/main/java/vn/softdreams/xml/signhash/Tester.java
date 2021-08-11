package vn.softdreams.xml.signhash;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;

import javax.crypto.Cipher;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.*;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class Tester {
    //Input
    String inputXmlFileName = "xmlChuaKy.xml";
    String p12FileName = "test.p12";
    String p12FilePass = "easykey";

    //Thông tin chứng thư số test
    private X509Certificate cert;
    private PrivateKey privateKey;
    private Certificate[] chain;

    //xml chưa ký
    private Document inputDoc;

    //Thông tin định dạng file xml đầu vào
    //Id của tag cha của tag cần ký
    String signedTagId;
    //Id của tag signature
    String signingTagId;
    //Namespace của file cần ký, inv:invoiceData -> namespace = inv
    String namespacePrefix;

    //output
    final String OUTPUT_FOLDER = "/Users/chen/Desktop/";

    public static void main(String[] args) {
        new Tester().doTest();
    }

    void initTest() throws Exception {
        //load xml và minimize
        loadXml();
        //load chứng thư để test
        loadP12(p12FileName, p12FilePass);
    }

    void doTest() {
        try {
            initTest();

            signedTagId = "inv:invoiceData";
            signingTagId = "buyer";
            namespacePrefix = "inv";

            //Hash trả về client ký
            HashOperator hashOperator = new HashOperator(inputDoc, cert, signedTagId, signingTagId, namespacePrefix);
            HashOperator.HashResponse response = hashOperator.performHash();
            String sessionId = response.getId();
            String b64Hash = response.getHash();

            //Giả lập ký tại client
            byte[] sig = signHash(Base64.getDecoder().decode(b64Hash), privateKey);
            String b64Signature = Base64.getEncoder().encodeToString(sig);

            //Đóng gói lại thành XML hoàn chỉnh
            Wrapper wrapper = new Wrapper();
            Document finalDoc = wrapper.wrapSignature(sessionId, b64Signature, signingTagId);
            //Ghi file
            String outputPath = OUTPUT_FOLDER + "signed_" + sessionId + ".xml";
            wrapper.write(finalDoc, outputPath, true);

            //Kiểm tra xml đã ký
//            Validator validator = new Validator();
//            boolean check = validator.verify(getFileFromResource("xmlDaKy.xml"));
//            System.out.println(check);
//            boolean isValid = validator.verify(new FileInputStream(new File(outputPath)));
//            System.out.println(isValid);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private InputStream getFileFromResource(String fileName) throws Exception {
        ClassLoader classLoader = getClass().getClassLoader();
        return classLoader.getResourceAsStream(fileName);
    }

    private void loadXml() throws Exception {
        InputStream xmlIs = getFileFromResource(inputXmlFileName);
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
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

//        inputDoc = dBuilder.parse(xmlIs);
        inputDoc = dBuilder.parse(new ByteArrayInputStream(minimizedXml.getBytes()));
        inputDoc.getDocumentElement().normalize();
        System.out.println("Test input doc, rootNode: " + inputDoc.getDocumentElement().getNodeName());
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

    //Hàm giả lập ký Hash, bản chất hàm này chạy ở client thông qua extension
    public byte[] signHash(byte[] hash, PrivateKey privateKey) throws Exception {
        Provider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", provider);
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return cipher.doFinal(hash);
    }
}
