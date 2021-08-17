package vn.softdreams.xml.signhash;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.File;

public class Wrapper {
    public Document wrapSignature(String sessionId, String signature, String signatureTagId) throws Exception {
        Document tempDoc = Cache.getInstance().get(sessionId);
        if (tempDoc == null) throw new Exception("Could not find document with given sessionId");
        //Xử lý trường hợp có nhiều thẻ SignatureValue, thẻ cần tìm có thẻ cha với ID = signingTagId
        NodeList sigValueList = tempDoc.getElementsByTagName("SignatureValue");
        if (signatureTagId == null || signatureTagId.isEmpty()) {
            //lấy node cuối cùng
            sigValueList.item(sigValueList.getLength() - 1).setTextContent(signature);
        } else {
            int index = -1;
            for (int i = 0; i < sigValueList.getLength(); i++) {
                //Kiểm tra thẻ cha id = $signatureTagId?
                Node parent = sigValueList.item(i).getParentNode();
                Node attrId = parent.getAttributes().getNamedItem("Id");
                if (attrId != null && attrId.getTextContent().equals(signatureTagId)) {
                    index = i;
                }
            }
            if (index == -1) throw new Exception("Could not find SignatureValue node for wrapping");
            sigValueList.item(index).setTextContent(signature);
        }
        return tempDoc;
    }

    public void write(Document doc, String outPath, boolean test) throws Exception {
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        DOMSource source = new DOMSource(doc);
        StreamResult result = new StreamResult(new File(outPath));
        transformer.transform(source, result);

        //Ghi ra console để test
        if (test) {
            StreamResult consoleResult = new StreamResult(System.out);
            transformer.transform(source, consoleResult);
        }
    }
}
