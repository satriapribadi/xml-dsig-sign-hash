package vn.softdreams.xml.signhash;

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
    String signatureTagId;
    //Id của tag signature
    String signingTagId;
    String signingTagName;
    //Namespace của file cần ký, inv:invoiceData -> namespace = inv
    String namespacePrefix;

    //output
    final String OUTPUT_FOLDER = "C:\\Users\\chen\\Desktop\\";

    public static void main(String[] args) {
        new Tester().doTest();
    }

    void initTest() throws Exception {
        //cài đặt cấu hình cho hóa đơn của CyberBill
        configureForCyberBill();
        //load xml và minimize
        loadXml();
        //load chứng thư để test
        loadP12(p12FileName, p12FilePass);
    }

    //options for work with CyberBill system
    void configureForCyberBill() {
        //bắt buộc
        signingTagId = "signingData";
        signingTagName = "inv:invoiceData";
        namespacePrefix = "inv";
        //option
        signatureTagId = "seller";
    }

    //with sample.xml file in resources folder
    void configureForSample() {
        signatureTagId = "";
        signingTagId = "signingData";
        namespacePrefix = "";
        signingTagName = "catalog";
    }

    void doTest() {
        try {
            initTest();
            //Hash trả về client ký
            HashOperator hashOperator = new HashOperator(inputDoc, cert, signingTagId, signingTagName, namespacePrefix);
            hashOperator.setSignatureTagId(signatureTagId);
            HashOperator.HashResponse response = hashOperator.performHash();
            String sessionId = response.getId();
            String b64Hash = response.getHash();

            //Giả lập ký tại client
            byte[] sig = signHash(Base64.getDecoder().decode(b64Hash), privateKey);
            String b64Signature = Base64.getEncoder().encodeToString(sig);

            //Đóng gói lại thành XML hoàn chỉnh
            Wrapper wrapper = new Wrapper();
            Document finalDoc = wrapper.wrapSignature(sessionId, b64Signature, signatureTagId);
            //Ghi file
            String outputPath = OUTPUT_FOLDER + "signed_" + sessionId + ".xml";
//            String outputPath = OUTPUT_FOLDER + "signed.xml";
            wrapper.write(finalDoc, outputPath, false);
            System.out.println("Sign process is done!");

            //Kiểm tra xml đã ký
            Validator validator = new Validator();
            boolean isValid = validator.verify(new FileInputStream(new File(outputPath)), signingTagName);
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
        if (signingTagName == null || signingTagName.isEmpty()) throw new Exception("SigningTagName must be defined");
        if (signingTagId == null || signatureTagId.isEmpty()) throw new Exception("SigningTagId must be defined");
        NodeList nl = inputDoc.getElementsByTagName(signingTagName);
        for (int i = 0; i < nl.getLength(); i++) {
            Node node = nl.item(i);
            if (node.getAttributes().getNamedItem("ID") == null) {
                Element element = (Element) node;
                element.setAttribute("ID", signingTagId);
            }
        }
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
