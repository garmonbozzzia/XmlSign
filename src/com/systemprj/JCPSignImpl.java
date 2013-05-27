package com.systemprj;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;

import javax.jws.WebService;
import javax.jws.WebMethod;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import ru.CryptoPro.JCPRequest.GostCertificateRequest;
import sun.misc.BASE64Encoder;


import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
//Service Implementation Bean

@WebService(endpointInterface = "com.systemprj.JCPSign")
public class JCPSignImpl implements JCPSign {

    private String alias = "MPT";
    private String keystoretype = "FloppyStore";
    private String keystorepass = "12345678";
    private String keystorepath = "";
    private String keypass = "12345678";
    /*
    private String alias = "Test";
    private String keystoretype = "HDImageStore";
    private String keystorepass = "123456";
    private String keystorepath = "/Users/grisha/.keystore_new";
    private String keypass = "";
     */

    public static void main(String[] Args)
    {
        try {
            JCPSignImpl impl = new JCPSignImpl();
                    String result = impl.signTest();
                    System.out.println(result);
        }
        catch (Exception exc)
        {
            System.out.println(exc.getMessage());
        }
    }

    final String signMethod =
            "http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411";
    final String digestMethod =
            "http://www.w3.org/2001/04/xmldsig-more#gostr3411";

    String getDocument_old()
    {
        return "<env:Envelope xmlns:env=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
                "   <env:Header/>\n" +
                "   <env:Body>\n" +
                "      <smev:getDocTypeResponse xmlns:smev=\"http://smevservice.webservices.gossrvc.samara.lanit.org\">\n" +
                "         <return xmlns:ns2=\"http://smevservice.webservices.gossrvc.samara.lanit.org/appData/rev111209/\" xmlns:ns3=\"http://samara.lanit.ru/gossrvc/schemas/ServiceRequest\" xmlns:ns4=\"http://smevservice.webservices.gossrvc.samara.lanit.org/xmldsig\" xmlns:ns5=\"http://smevservice.webservices.gossrvc.samara.lanit.org/xop/include\" xmlns:ns6=\"http://smevservice.webservices.gossrvc.samara.lanit.org/rev111209\">\n" +
                "            <ns6:Message>\n" +
                "               <ns6:Sender/>\n" +
                "               <ns6:Recipient>\n" +
                "                  <ns6:Code>10000001077</ns6:Code>\n" +
                "                  <ns6:Name>МЭР</ns6:Name>\n" +
                "               </ns6:Recipient>\n" +
                "               <ns6:TypeCode>5</ns6:TypeCode>\n" +
                "               <ns6:ServiceCode>10000978231</ns6:ServiceCode>\n" +
                "            </ns6:Message>\n" +
                "            <ns6:MessageData>\n" +
                "               <ns6:AppData>\n" +
                "                  <ns2:SmevRequest>\n" +
                "                     <ns2:serviceId>UsSoz000000000001</ns2:serviceId>\n" +
                "                  </ns2:SmevRequest>\n" +
                "                  <ns2:SmevResponse>\n" +
                "                     <ns2:DocPackage>\n" +
                "                        <ns2:typeItems>\n" +
                "                           <ns2:title>Заявление о назначении и выплате ежемесячной денежной выплаты</ns2:title>\n" +
                "                           <ns2:docTypeId>TiDocZajav0003</ns2:docTypeId>\n" +
                "                           <ns2:docClassId>original</ns2:docClassId>\n" +
                "                           <ns2:required>true</ns2:required>\n" +
                "                        </ns2:typeItems>\n" +
                "                        <ns2:typeItems>\n" +
                "                           <ns2:title>Документ, удостоверяющий личность заявителя (пакет документов №1), а именно один из следующих</ns2:title>\n" +
                "                           <ns2:docTypeId>TiDocUdLichnosti1</ns2:docTypeId>\n" +
                "                           <ns2:docClassId>copy</ns2:docClassId>\n" +
                "                           <ns2:required>true</ns2:required>\n" +
                "                        </ns2:typeItems>\n" +
                "                        <ns2:typeItems>\n" +
                "                           <ns2:title>Документ, подтверждающий факт проживания заявителя на территории Смоленской области (пакет документов №1), а именно один из следующих</ns2:title>\n" +
                "                           <ns2:docTypeId>TiDocZajavitKostrom</ns2:docTypeId>\n" +
                "                           <ns2:docClassId>copy</ns2:docClassId>\n" +
                "                           <ns2:required>true</ns2:required>\n" +
                "                        </ns2:typeItems>\n" +
                "                        <ns2:typeItems>\n" +
                "                           <ns2:title>Свидетельство о рождении ребенка</ns2:title>\n" +
                "                           <ns2:docTypeId>TiDocSvidRbRozhd</ns2:docTypeId>\n" +
                "                           <ns2:docClassId>copy</ns2:docClassId>\n" +
                "                           <ns2:required>true</ns2:required>\n" +
                "                        </ns2:typeItems>\n" +
                "                        <ns2:typeItems>\n" +
                "                           <ns2:title>Справка из медицинской организации, подтверждающая перевод ребенка на искусственное или смешанное вскармливание</ns2:title>\n" +
                "                           <ns2:docTypeId>TiDocSpravEdaIsRb1</ns2:docTypeId>\n" +
                "                           <ns2:docClassId>original</ns2:docClassId>\n" +
                "                           <ns2:required>true</ns2:required>\n" +
                "                        </ns2:typeItems>\n" +
                "                        <ns2:typeItems>\n" +
                "                           <ns2:title>Справка о составе семьи (совместном проживании)</ns2:title>\n" +
                "                           <ns2:docTypeId>TiDocSpravSemyaSstv</ns2:docTypeId>\n" +
                "                           <ns2:docClassId>original</ns2:docClassId>\n" +
                "                           <ns2:required>true</ns2:required>\n" +
                "                        </ns2:typeItems>\n" +
                "                        <ns2:typeItems>\n" +
                "                           <ns2:title>Документ, удостоверяющий права (полномочия) представителя физического или юридического лица (в случае обращения с заявлением представителя заявителя).</ns2:title>\n" +
                "                           <ns2:docTypeId>TiDocPredstavitZayav</ns2:docTypeId>\n" +
                "                           <ns2:docClassId>copy</ns2:docClassId>\n" +
                "                           <ns2:required>false</ns2:required>\n" +
                "                        </ns2:typeItems>\n" +
                "                        <ns2:typeItems>\n" +
                "                           <ns2:title>Постановление органов местного самоуправления об установлении опеки над ребенком (детьми)</ns2:title>\n" +
                "                           <ns2:docTypeId>TiDocVypiskOpeki1</ns2:docTypeId>\n" +
                "                           <ns2:docClassId>copy</ns2:docClassId>\n" +
                "                           <ns2:required>false</ns2:required>\n" +
                "                        </ns2:typeItems>\n" +
                "                        <ns2:typeItems>\n" +
                "                           <ns2:title>Уведомление об отказе в назначении ежемесячной денежной выплаты</ns2:title>\n" +
                "                           <ns2:docTypeId>TiDocUvOtk0003</ns2:docTypeId>\n" +
                "                           <ns2:docClassId>original</ns2:docClassId>\n" +
                "                           <ns2:required>false</ns2:required>\n" +
                "                        </ns2:typeItems>\n" +
                "                        <ns2:typeItems>\n" +
                "                           <ns2:title>Уведомление о назначении ежемесячной денежной выплаты</ns2:title>\n" +
                "                           <ns2:docTypeId>TiDocUvPrd0003</ns2:docTypeId>\n" +
                "                           <ns2:docClassId>original</ns2:docClassId>\n" +
                "                           <ns2:required>false</ns2:required>\n" +
                "                        </ns2:typeItems>\n" +
                "                        <ns2:typeItems>\n" +
                "                           <ns2:title>Свидетельство об усыновлении, либо вступившее в законную силу решение суда об усыновлении ребенка (детей)</ns2:title>\n" +
                "                           <ns2:docTypeId>TiDocReshSudUs</ns2:docTypeId>\n" +
                "                           <ns2:docClassId>copy</ns2:docClassId>\n" +
                "                           <ns2:required>false</ns2:required>\n" +
                "                        </ns2:typeItems>\n" +
                "                        <ns2:typeItems>\n" +
                "                           <ns2:title>Уведомление о прекращении выплаты ежемесячной денежной выплаты</ns2:title>\n" +
                "                           <ns2:docTypeId>TiDocUvPrk0002</ns2:docTypeId>\n" +
                "                           <ns2:docClassId>original</ns2:docClassId>\n" +
                "                           <ns2:required>false</ns2:required>\n" +
                "                        </ns2:typeItems>\n" +
                "                        <ns2:typeItems>\n" +
                "                           <ns2:title>Уведомление о внесении изменений в персональные данные или выплатные реквизиты заявителя</ns2:title>\n" +
                "                           <ns2:docTypeId>TiDocUvIzm0001</ns2:docTypeId>\n" +
                "                           <ns2:docClassId>original</ns2:docClassId>\n" +
                "                           <ns2:required>false</ns2:required>\n" +
                "                        </ns2:typeItems>\n" +
                "                        <ns2:typeItems>\n" +
                "                           <ns2:title>Сберегательная книжка (титульный лист), копия договора или номер счета, открытого в кредитной организации (в случае перечисления средств на счет кредитной организации)</ns2:title>\n" +
                "                           <ns2:docTypeId>TiDocSchSbBank</ns2:docTypeId>\n" +
                "                           <ns2:docClassId>copy</ns2:docClassId>\n" +
                "                           <ns2:required>false</ns2:required>\n" +
                "                        </ns2:typeItems>\n" +
                "                     </ns2:DocPackage>\n" +
                "                  </ns2:SmevResponse>\n" +
                "                  <ns4:Signature>\n" +
                "                     <ns4:SignedInfo>\n" +
                "                        <ns4:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "                        <ns4:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411\"/>\n" +
                "                        <ns4:Reference URI=\"#bodyId\">\n" +
                "                           <ns4:Transforms>\n" +
                "                              <ns4:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "                           </ns4:Transforms>\n" +
                "                           <ns4:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#gostr3411\"/>\n" +
                "                           <ns4:DigestValue>yit9cMxRhYhn6ZegkBQcx0m1Vq8QoARZrypSJQb3Ajc=</ns4:DigestValue>\n" +
                "                        </ns4:Reference>\n" +
                "                     </ns4:SignedInfo>\n" +
                "                     <ns4:SignatureValue>yGjD43wk6V8jetRKBY3qywB6bkP3iZnUMVgqOS80n21r99q6Est4nIaGuodFeXnQe4vGGGokDzUj2OVcWqDMyw==</ns4:SignatureValue>\n" +
                "                     <ns4:KeyInfo>\n" +
                "                        <xd:SecurityTokenReference xmlns:xd=\"http://smevservice.webservices.gossrvc.samara.lanit.org/xmldsig\">\n" +
                "                           <xd:Reference URI=\"#AisOguCert\" ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\"/>\n" +
                "                        </xd:SecurityTokenReference>\n" +
                "                     </ns4:KeyInfo>\n" +
                "                  </ns4:Signature>\n" +
                "               </ns6:AppData>\n" +
                "               <ns6:AppDocument/>\n" +
                "            </ns6:MessageData>\n" +
                "         </return>\n" +
                "         <parameters xmlns:ns2=\"http://smevservice.webservices.gossrvc.samara.lanit.org/appData/rev111209/\" xmlns:ns3=\"http://samara.lanit.ru/gossrvc/schemas/ServiceRequest\" xmlns:ns4=\"http://smevservice.webservices.gossrvc.samara.lanit.org/xmldsig\" xmlns:ns5=\"http://smevservice.webservices.gossrvc.samara.lanit.org/xop/include\" xmlns:ns6=\"http://smevservice.webservices.gossrvc.samara.lanit.org/rev111209\">\n" +
                "            <ns6:Message>\n" +
                "               <ns6:Sender/>\n" +
                "               <ns6:Recipient>\n" +
                "                  <ns6:Code>10000001077</ns6:Code>\n" +
                "                  <ns6:Name>МЭР</ns6:Name>\n" +
                "               </ns6:Recipient>\n" +
                "               <ns6:TypeCode>5</ns6:TypeCode>\n" +
                "               <ns6:ServiceCode>10000978231</ns6:ServiceCode>\n" +
                "            </ns6:Message>\n" +
                "            <ns6:MessageData>\n" +
                "               <ns6:AppData>\n" +
                "                  <ns2:SmevRequest>\n" +
                "                     <ns2:serviceId>UsSoz000000000001</ns2:serviceId>\n" +
                "                  </ns2:SmevRequest>\n" +
                "                  <ns2:SmevResponse>\n" +
                "                     <ns2:DocPackage>\n" +
                "                        <ns2:typeItems>\n" +
                "                           <ns2:title>Заявление о назначении и выплате ежемесячной денежной выплаты</ns2:title>\n" +
                "                           <ns2:docTypeId>TiDocZajav0003</ns2:docTypeId>\n" +
                "                           <ns2:docClassId>original</ns2:docClassId>\n" +
                "                           <ns2:required>true</ns2:required>\n" +
                "                        </ns2:typeItems>\n" +
                "                        <ns2:typeItems>\n" +
                "                           <ns2:title>Документ, удостоверяющий личность заявителя (пакет документов №1), а именно один из следующих</ns2:title>\n" +
                "                           <ns2:docTypeId>TiDocUdLichnosti1</ns2:docTypeId>\n" +
                "                           <ns2:docClassId>copy</ns2:docClassId>\n" +
                "                           <ns2:required>true</ns2:required>\n" +
                "                        </ns2:typeItems>\n" +
                "                        <ns2:typeItems>\n" +
                "                           <ns2:title>Документ, подтверждающий факт проживания заявителя на территории Смоленской области (пакет документов №1), а именно один из следующих</ns2:title>\n" +
                "                           <ns2:docTypeId>TiDocZajavitKostrom</ns2:docTypeId>\n" +
                "                           <ns2:docClassId>copy</ns2:docClassId>\n" +
                "                           <ns2:required>true</ns2:required>\n" +
                "                        </ns2:typeItems>\n" +
                "                        <ns2:typeItems>\n" +
                "                           <ns2:title>Свидетельство о рождении ребенка</ns2:title>\n" +
                "                           <ns2:docTypeId>TiDocSvidRbRozhd</ns2:docTypeId>\n" +
                "                           <ns2:docClassId>copy</ns2:docClassId>\n" +
                "                           <ns2:required>true</ns2:required>\n" +
                "                        </ns2:typeItems>\n" +
                "                        <ns2:typeItems>\n" +
                "                           <ns2:title>Справка из медицинской организации, подтверждающая перевод ребенка на искусственное или смешанное вскармливание</ns2:title>\n" +
                "                           <ns2:docTypeId>TiDocSpravEdaIsRb1</ns2:docTypeId>\n" +
                "                           <ns2:docClassId>original</ns2:docClassId>\n" +
                "                           <ns2:required>true</ns2:required>\n" +
                "                        </ns2:typeItems>\n" +
                "                        <ns2:typeItems>\n" +
                "                           <ns2:title>Справка о составе семьи (совместном проживании)</ns2:title>\n" +
                "                           <ns2:docTypeId>TiDocSpravSemyaSstv</ns2:docTypeId>\n" +
                "                           <ns2:docClassId>original</ns2:docClassId>\n" +
                "                           <ns2:required>true</ns2:required>\n" +
                "                        </ns2:typeItems>\n" +
                "                        <ns2:typeItems>\n" +
                "                           <ns2:title>Документ, удостоверяющий права (полномочия) представителя физического или юридического лица (в случае обращения с заявлением представителя заявителя).</ns2:title>\n" +
                "                           <ns2:docTypeId>TiDocPredstavitZayav</ns2:docTypeId>\n" +
                "                           <ns2:docClassId>copy</ns2:docClassId>\n" +
                "                           <ns2:required>false</ns2:required>\n" +
                "                        </ns2:typeItems>\n" +
                "                        <ns2:typeItems>\n" +
                "                           <ns2:title>Постановление органов местного самоуправления об установлении опеки над ребенком (детьми)</ns2:title>\n" +
                "                           <ns2:docTypeId>TiDocVypiskOpeki1</ns2:docTypeId>\n" +
                "                           <ns2:docClassId>copy</ns2:docClassId>\n" +
                "                           <ns2:required>false</ns2:required>\n" +
                "                        </ns2:typeItems>\n" +
                "                        <ns2:typeItems>\n" +
                "                           <ns2:title>Уведомление об отказе в назначении ежемесячной денежной выплаты</ns2:title>\n" +
                "                           <ns2:docTypeId>TiDocUvOtk0003</ns2:docTypeId>\n" +
                "                           <ns2:docClassId>original</ns2:docClassId>\n" +
                "                           <ns2:required>false</ns2:required>\n" +
                "                        </ns2:typeItems>\n" +
                "                        <ns2:typeItems>\n" +
                "                           <ns2:title>Уведомление о назначении ежемесячной денежной выплаты</ns2:title>\n" +
                "                           <ns2:docTypeId>TiDocUvPrd0003</ns2:docTypeId>\n" +
                "                           <ns2:docClassId>original</ns2:docClassId>\n" +
                "                           <ns2:required>false</ns2:required>\n" +
                "                        </ns2:typeItems>\n" +
                "                        <ns2:typeItems>\n" +
                "                           <ns2:title>Свидетельство об усыновлении, либо вступившее в законную силу решение суда об усыновлении ребенка (детей)</ns2:title>\n" +
                "                           <ns2:docTypeId>TiDocReshSudUs</ns2:docTypeId>\n" +
                "                           <ns2:docClassId>copy</ns2:docClassId>\n" +
                "                           <ns2:required>false</ns2:required>\n" +
                "                        </ns2:typeItems>\n" +
                "                        <ns2:typeItems>\n" +
                "                           <ns2:title>Уведомление о прекращении выплаты ежемесячной денежной выплаты</ns2:title>\n" +
                "                           <ns2:docTypeId>TiDocUvPrk0002</ns2:docTypeId>\n" +
                "                           <ns2:docClassId>original</ns2:docClassId>\n" +
                "                           <ns2:required>false</ns2:required>\n" +
                "                        </ns2:typeItems>\n" +
                "                        <ns2:typeItems>\n" +
                "                           <ns2:title>Уведомление о внесении изменений в персональные данные или выплатные реквизиты заявителя</ns2:title>\n" +
                "                           <ns2:docTypeId>TiDocUvIzm0001</ns2:docTypeId>\n" +
                "                           <ns2:docClassId>original</ns2:docClassId>\n" +
                "                           <ns2:required>false</ns2:required>\n" +
                "                        </ns2:typeItems>\n" +
                "                        <ns2:typeItems>\n" +
                "                           <ns2:title>Сберегательная книжка (титульный лист), копия договора или номер счета, открытого в кредитной организации (в случае перечисления средств на счет кредитной организации)</ns2:title>\n" +
                "                           <ns2:docTypeId>TiDocSchSbBank</ns2:docTypeId>\n" +
                "                           <ns2:docClassId>copy</ns2:docClassId>\n" +
                "                           <ns2:required>false</ns2:required>\n" +
                "                        </ns2:typeItems>\n" +
                "                     </ns2:DocPackage>\n" +
                "                  </ns2:SmevResponse>\n" +
                "                  <ns4:Signature>\n" +
                "                     <ns4:SignedInfo>\n" +
                "                        <ns4:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "                        <ns4:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411\"/>\n" +
                "                        <ns4:Reference URI=\"#bodyId\">\n" +
                "                           <ns4:Transforms>\n" +
                "                              <ns4:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "                           </ns4:Transforms>\n" +
                "                           <ns4:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#gostr3411\"/>\n" +
                "                           <ns4:DigestValue>yit9cMxRhYhn6ZegkBQcx0m1Vq8QoARZrypSJQb3Ajc=</ns4:DigestValue>\n" +
                "                        </ns4:Reference>\n" +
                "                     </ns4:SignedInfo>\n" +
                "                     <ns4:SignatureValue>yGjD43wk6V8jetRKBY3qywB6bkP3iZnUMVgqOS80n21r99q6Est4nIaGuodFeXnQe4vGGGokDzUj2OVcWqDMyw==</ns4:SignatureValue>\n" +
                "                     <ns4:KeyInfo>\n" +
                "                        <xd:SecurityTokenReference xmlns:xd=\"http://smevservice.webservices.gossrvc.samara.lanit.org/xmldsig\">\n" +
                "                           <xd:Reference URI=\"#AisOguCert\" ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\"/>\n" +
                "                        </xd:SecurityTokenReference>\n" +
                "                     </ns4:KeyInfo>\n" +
                "                  </ns4:Signature>\n" +
                "               </ns6:AppData>\n" +
                "               <ns6:AppDocument/>\n" +
                "            </ns6:MessageData>\n" +
                "         </parameters>\n" +
                "      </smev:getDocTypeResponse>\n" +
                "   </env:Body>\n" +
                "</env:Envelope>";
    }
    String getDocument() throws Exception
    {
        return new String("<S:Envelope xmlns:S=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"><S:Header><wsse:Security S:actor=\"http://smev.gosuslugi.ru/actors/smev\"><wsse:BinarySecurityToken EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\" ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\" wsu:Id=\"CertId\">MIIFtzCCBWagAwIBAgIDIk6iMAgGBiqFAwICAzCCAfYxGTAXBgNVBAQMENCc0LXQtNCy0LXQtNC10LIxLDAqBgNVBCoMI9CQ0L3QsNGC0L7Qu9C40Lkg0JHQvtGA0LjRgdC+0LLQuNGHMRkwFwYDVQQHDBDQsy4g0JzQvtGB0LrQstCwMSMwIQYDVQQJDBrRg9C7LiDQmNC70YzQuNC90LrQsCwg0LQuOTGBojCBnwYJKoZIhvcNAQkCDIGR0JTQsNC90L3Ri9C5INGB0LXRgNGC0LjRhNC40LrQsNGCINC+0YLQutGA0YvRgtC+0LPQviDQutC70Y7Rh9CwINC40YHQv9C+0LvRjNC30YPQtdGC0YHRjyDRgdC+INGB0YDQtdC00YHRgtCy0L7QvCDQodCa0JfQmCDQmtGA0LjQv9GC0L4g0J/RgNC+IENTUDELMAkGA1UEBhMCUlUxODA2BgNVBAoML9Ck0LXQtNC10YDQsNC70YzQvdC+0LUg0LrQsNC30L3QsNGH0LXQudGB0YLQstC+MX8wfQYDVQQDDHbQo9C/0L7Qu9C90L7QvNC+0YfQtdC90L3Ri9C5INGD0LTQvtGB0YLQvtCy0LXRgNGP0Y7RidC40Lkg0YbQtdC90YLRgCDQpNC10LTQtdGA0LDQu9GM0L3QvtCz0L4g0LrQsNC30L3QsNGH0LXQudGB0YLQstCwMB4XDTExMDMyNDEyMjUxOVoXDTEyMDMyMzEyMjUxOVowggFhMQswCQYDVQQGEwJSVTEZMBcGA1UECAwQ0LMuINCc0L7RgdC60LLQsDEVMBMGA1UEBwwM0JzQvtGB0LrQstCwMU4wTAYDVQQKDEXQpNCV0JTQldCg0JDQm9Cs0J3QntCVINCa0JDQl9Cd0JDQp9CV0JnQodCi0JLQniAo0KHQldCg0JLQldCgINCh0K3QlCkxJjAkBgNVBCoMHdCu0LvQuNGPINCT0LXQvtGA0LPQuNC10LLQvdCwMRkwFwYDVQQEDBDQmtC+0L/Ri9C70L7QstCwMSgwJgYDVQQMDB/QndCw0YfQsNC70YzQvdC40Log0L7RgtC00LXQu9CwMWMwYQYDVQQDDFrQmtC+0L/Ri9C70L7QstCwINCu0LvQuNGPINCT0LXQvtGA0LPQuNC10LLQvdCwICjQotC10YXQvdC+0LvQvtCz0LjRh9C10YHQutC40Lkg0LrQu9GO0YcgMSkwYzAcBgYqhQMCAhMwEgYHKoUDAgIkAAYHKoUDAgIeAQNDAARAy9OoVph+gGTflOV66d6sHiDwdANt+vNhXwx0KnDK2sbSl041RBV0S578k3fZrdIhkacz1AeDKyQHKxzyWs46zqOCAWowggFmMAwGA1UdEwEB/wQCMAAwGAYDVR0gBBEwDzANBgsqhQMDPZ7XNgECAjBjBgNVHREEXDBaoBIGA1UEDKALEwkzMjQxMzUzNTeGATCgDgYIKoUDA4EDAQGgAhMAoBAGCiqFAwM9ntc2AQegAhMAoBAGCiqFAwM9ntc2AQWgAhMAoA0GByqFAwHgOQGgAhMAMA4GA1UdDwEB/wQEAwIE0DAhBgNVHSUEGjAYBggqhQMCAQYIBQYMKoUDAz2e1zYBBgMCMB8GA1UdIwQYMBaAFAe1ebcBOgyBvSWBc6saQOlYw/NNMGQGA1UdHwRdMFswLqAsoCqGKGh0dHA6Ly9kYy51Yy1zZnNmay5sb2NhbC9jcmwvY3VycmVudC5jcmwwKaAnoCWGI2h0dHA6Ly9jcmwucm9za2F6bmEucnUvY3JsL2xhc3QuY3JsMB0GA1UdDgQWBBQ6BizcjJIKBIGuyz7OCdySYtSE4zAIBgYqhQMCAgMDQQDRsa8Xu7mdTyKxrsVEr9YqGo2iG7Bcj1v4ttgcY+ylS3o9htFVhqu/TVXG90tTiFbR5f4j69/5y9YCkXaiGHdV</wsse:BinarySecurityToken><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411\"></ds:SignatureMethod><ds:Reference URI=\"#body\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#gostr3411\"></ds:DigestMethod><ds:DigestValue>j/09e90aqAaJd3iNVIXAx1ZveytZFCI+VVPEFwoC4j4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>jyAnuWfHRiYtCykHJmFIqD1iId7dkqpiDPyGvrmRkuA0DqmGJOQeiZXs3IigRqYSwD4CoxQQh8u2Dg7AFQcN8A==</ds:SignatureValue><ds:KeyInfo><wsse:SecurityTokenReference><wsse:Reference URI=\"#CertId\" ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\"></wsse:Reference></wsse:SecurityTokenReference></ds:KeyInfo></ds:Signature></wsse:Security></S:Header><S:Body wsu:Id=\"body\"><ns9:UnifoTransferMsg xmlns:ns10=\"http://roskazna.ru/xsd/ExportQuittanceResponse\" xmlns:ns11=\"http://roskazna.ru/xsd/ExportIncomesResponse\" xmlns:ns12=\"http://roskazna.ru/xsd/ExportPaymentsResponse\" xmlns:ns13=\"http://roskazna.ru/xsd/PGU_ChargesResponse\" xmlns:ns14=\"http://roskazna.ru/xsd/PaymentInfo\" xmlns:ns15=\"http://roskazna.ru/xsd/Charge\" xmlns:ns2=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:ns3=\"http://smev.gosuslugi.ru/rev110801\" xmlns:ns4=\"http://roskazna.ru/xsd/PGU_ImportRequest\" xmlns:ns5=\"http://rosrazna.ru/xsd/SmevUnifoService\" xmlns:ns6=\"http://roskazna.ru/xsd/Ticket\" xmlns:ns7=\"http://roskazna.ru/xsd/PGU_DataRequest\" xmlns:ns8=\"http://www.w3.org/2004/08/xop/include\" xmlns:ns9=\"http://roskazna.ru/SmevUnifoService/\"><ns3:Message><ns3:Sender><ns3:Code>0000000001</ns3:Code><ns3:Name>External Organization</ns3:Name></ns3:Sender><ns3:Recipient><ns3:Code>0000000000</ns3:Code><ns3:Name>UNIFO</ns3:Name></ns3:Recipient><ns3:Originator><ns3:Code>0000000001фыва</ns3:Code><ns3:Name>External Organization</ns3:Name></ns3:Originator><ns3:TypeCode>Request</ns3:TypeCode><ns3:Date>2011-09-08T11:26:40.137+04:00</ns3:Date></ns3:Message><ns3:MessageData><ns3:AppData><ns5:exportData><ns7:DataRequest kind=\"CHARGESTATUS\"><PostBlock><ID>055aa777-b988-4503-8ad9-e4eed14e7a06</ID><TimeStamp>2011-09-08T11:26:41.247+04:00</TimeStamp><SenderIdentifier>044525225</SenderIdentifier></PostBlock><SupplierBillIDs><SupplierBillID>18800000000000122936</SupplierBillID></SupplierBillIDs></ns7:DataRequest></ns5:exportData></ns3:AppData></ns3:MessageData></ns9:UnifoTransferMsg></S:Body></S:Envelope>".getBytes("utf-8"), "utf-8");
    }

    //final String alias = "Test";

    @WebMethod
    public String signTest() throws Exception
    {
        return signXML(getDocument());
    }

    @WebMethod
    public String signXML(String document)throws Exception
    {
        X509Certificate cert;
        PrivateKey privateKey;

        KeyStore ks = getKeyStore();
        privateKey = (PrivateKey)ks.getKey(alias, keypass == "" ? null : keypass.toCharArray());
        cert = (X509Certificate)ks.getCertificateChain(alias)[0];
        return signOnlyHead(document, privateKey, cert);
    }

    @WebMethod
    public String signXML2(String document)throws Exception
    {
        X509Certificate cert;
        PrivateKey privateKey;

        KeyStore ks = getKeyStore();
        privateKey = (PrivateKey)ks.getKey(alias, keypass == "" ? null : keypass.toCharArray());
        cert = (X509Certificate)ks.getCertificateChain(alias)[0];
        return sign(document, privateKey, cert);
    }

    KeyStore getKeyStore() throws Exception
    {

        KeyStore ks = KeyStore.getInstance(keystoretype, "JCP");
        FileInputStream is = null;
        if(keystoretype == "HDImageStore"){
            is = new FileInputStream(keystorepath);
        }
        ks.load(is, keystorepass.toCharArray());
        return ks;
    }

    void signAppData(Document document, PrivateKey privateKey, X509Certificate cert) throws Exception
    {
        Element appData = (Element)document.getElementsByTagNameNS("*","AppData").item(0);


        NamedNodeMap attrs = appData.getAttributes();

        String idAttr = "";
        for(int i = 0, l = attrs.getLength(); i < l; i++){
            if(attrs.item(i).getNodeName().contains("Id")){
                idAttr = attrs.item(i).getNodeValue();
            }

        }



        //signElement(document, privateKey, cert, "#AppData", appData );
        XMLSignature sig =  new XMLSignature(document, "", signMethod);
        appData.insertBefore(sig.getElement(), appData.getFirstChild());
        final Transforms transforms = new Transforms(document);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        transforms.addTransform(Transforms.TRANSFORM_C14N_WITH_COMMENTS);
        sig.addDocument("#"+idAttr, transforms, digestMethod);
        sig.addKeyInfo(cert);
        sig.sign(privateKey);

    }

    void signHeader(Document document, PrivateKey privateKey, X509Certificate cert) throws Exception
    {
        final Element anElement = (Element)(document.getDocumentElement().getFirstChild());

        System.out.println("------\n"+ nsName(document)+ "\n------");

        Element security = document.createElement("wsse:Security");
        security.setAttribute(nsName(document) + ":actor","http://smev.gosuslugi.ru/actors/smev");
        anElement.appendChild(security);

        addBST(document, security, cert);
        //signElement(document, privateKey, cert, "#body", security );

        XMLSignature sig =  new XMLSignature(document, "", signMethod);
        security.appendChild(sig.getElement());
        final Transforms transforms = new Transforms(document);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        transforms.addTransform(Transforms.TRANSFORM_C14N_WITH_COMMENTS);
        sig.addDocument("#body", transforms, digestMethod);
        addSecurityTokenReference(document, sig.getKeyInfo().getElement());
        sig.sign(privateKey);
    }

    Document parseXML(String document) throws Exception
    {
        InputStream is = new ByteArrayInputStream(document.getBytes("utf-8"));

        final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setIgnoringElementContentWhitespace(true);
        dbf.setCoalescing(true);
        dbf.setNamespaceAware(true);

        final DocumentBuilder documentBuilder = dbf.newDocumentBuilder();

        return documentBuilder.parse(is);
    }

    String getSignedDocument(Document document) throws Exception
    {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        final TransformerFactory tf = TransformerFactory.newInstance();
        final Transformer trans = tf.newTransformer();
        trans.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
        trans.transform(new DOMSource(document), new StreamResult(os));
        os.close();
        return os.toString("UTF-8");
    }

    String sign(String document, PrivateKey privateKey, X509Certificate cert)throws Exception
    {
        ru.CryptoPro.JCPxml.XmlInit.init();

        Document docXML = parseXML(document);
        signHeader(docXML, privateKey,cert);
        signAppData(docXML, privateKey, cert);
        return getSignedDocument(docXML);
    }

    String signOnlyHead(String document, PrivateKey privateKey, X509Certificate cert)throws Exception
    {
        ru.CryptoPro.JCPxml.XmlInit.init();

        Document docXML = parseXML(document);
        signHeader(docXML, privateKey,cert);

        return getSignedDocument(docXML);
    }

    Element addBST( Document doc, Element parentElement, X509Certificate certificate) throws Exception
    {
        String XSD_WSSE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";

        Element bst = doc.createElement("wsse:BinarySecurityToken");

        bst.setAttribute("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
        bst.setAttribute("EncodingType", "wsse:Base64Binary");
        bst.setAttribute("wsu:Id", "CertId");

        BASE64Encoder encoder=new BASE64Encoder();
        String psB64Certificate = encoder.encodeBuffer(certificate.getEncoded());
        bst.setTextContent(psB64Certificate);

        parentElement.appendChild(bst);
        return bst;
    }

    void addSecurityTokenReference(Document doc, Element keyInfo)throws Exception
    {
        //addSecurityTokenReference securityTokenReference_ = new addSecurityTokenReference(bst);
        Element securityTokenReference = doc.createElement("wsse:addSecurityTokenReference");
        keyInfo.appendChild(securityTokenReference);
        Element reference = doc.createElement("wsse:Reference");
        securityTokenReference.appendChild(reference);
        reference.setAttribute("URI", "#CertId");
        reference.setAttribute("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
    }

    String nsName(Document document) throws Exception
    {
       String tagName = document.getDocumentElement().getTagName();
       return tagName.substring(0,tagName.indexOf(":"));
    }
}