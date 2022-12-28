package vn.softdreams.xml.signhash;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.File;

public class Wrapper {
    public Document wrapSignature(String sessionId, String signature) throws Exception {
        Document tempDoc = Cache.getInstance().get(sessionId);
        if (tempDoc == null) throw new Exception("Could not find document with given sessionId");
        NodeList sigValueList = tempDoc.getElementsByTagName("SignatureValue");
        sigValueList.item(sigValueList.getLength() - 1).setTextContent(signature);
        return tempDoc;
    }

    public void write(Document doc, String outPath, boolean test) throws Exception {
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        DOMSource source = new DOMSource(doc);
        StreamResult result = new StreamResult(new File(outPath));
        transformer.transform(source, result);

        if (test) {
            StreamResult consoleResult = new StreamResult(System.out);
            transformer.transform(source, consoleResult);
        }
    }
}
