package edu.utn.frba.grupo5303.wsaacliente;

// El Departamento de Seguridad Informatica de la AFIP (DeSeIn/AFIP), pone a disposicion
// el siguiente codigo para su utilizacion con el WebService de Autenticacion y Autorizacion
// de la AFIP.
//
// El mismo no puede ser re-distribuido, publicado o descargado en forma total o parcial, ya sea
// en forma electronica, mecanica u optica, sin la autorizacion de DeSeIn/AFIP. El uso no
// autorizado del mismo esta prohibido.
//
// DeSeIn/AFIP no asume ninguna responsabilidad de los errores que pueda contener el codigo ni la
// obligacion de subsanar dichos errores o informar de la existencia de los mismos.
//
// DeSeIn/AFIP no asume ninguna responsabilidad que surja de la utilizacion del codigo, ya sea por
// utilizacion ilegal de patentes, perdida de beneficios, perdida de informacion o cualquier otro
// inconveniente.
//
// Bajo ninguna circunstancia DeSeIn/AFIP podra ser indicada como responsable por consecuencias y/o
// incidentes ya sean directos o indirectos que puedan surgir de la utilizacion del codigo.
//
// DeSeIn/AFIP no da ninguna garantia, expresa o implicita, de la utilidad del codigo, si el mismo es
// correcto, o si cumple con los requerimientos de algun proposito en particular.
//
// DeSeIn/AFIP puede realizar cambios en cualquier momento en el codigo sin previo aviso.
//
// El codigo debera ser evaluado, verificado, corregido y/o adaptado por personal tecnico calificado
// de las entidades que lo utilicen.
//
// EL SIGUIENTE CODIGO ES DISTRIBUIDO PARA EVALUACION, CON TODOS SUS ERRORES Y OMISIONES. LA
// RESPONSABILIDAD DEL CORRECTO FUNCIONAMIENTO DEL MISMO YA SEA POR SI SOLO O COMO PARTE DE
// OTRA APLICACION, QUEDA A CARGO DE LAS ENTIDADES QUE LO UTILICEN. LA UTILIZACION DEL CODIGO
// SIGNIFICA LA ACEPTACION DE TODOS LOS TERMINOS Y CONDICIONES MENCIONADAS ANTERIORMENTE.
//
// Version 1.0
// gp/rg/OF.G. DeSeIn-AFIP
//
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.GregorianCalendar;

import org.apache.axis.client.Call;
import org.apache.axis.client.Service;
import org.apache.axis.encoding.Base64;
import org.apache.axis.encoding.XMLType;

import com.sun.org.apache.xerces.internal.jaxp.datatype.XMLGregorianCalendarImpl;
import fev1.dif.afip.gov.ar.AlicIva;
import fev1.dif.afip.gov.ar.ArrayOfAlicIva;
import fev1.dif.afip.gov.ar.ArrayOfFECAEDetRequest;
import fev1.dif.afip.gov.ar.FEAuthRequest;
import fev1.dif.afip.gov.ar.FECAECabRequest;
import fev1.dif.afip.gov.ar.FECAEDetRequest;
import fev1.dif.afip.gov.ar.FECAERequest;
import fev1.dif.afip.gov.ar.FECAEResponse;
import fev1.dif.afip.gov.ar.FECAESolicitar;
import fev1.dif.afip.gov.ar.FECAESolicitarResponse;
import fev1.dif.afip.gov.ar.FECompUltimoAutorizado;
import fev1.dif.afip.gov.ar.FECompUltimoAutorizadoResponse;
import fev1.dif.afip.gov.ar.FEParamGetTiposCbteResponse;
import fev1.dif.afip.gov.ar.FERecuperaLastCbteResponse;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.URL;
import java.net.URLConnection;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.PropertyException;
import javax.xml.bind.Unmarshaller;
import javax.xml.rpc.ParameterMode;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class afip_wsaa_client {

    private static String token = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9InllcyI/Pgo8c3NvIHZlcnNpb249IjIuMCI+CiAgICA8aWQgdW5pcXVlX2lkPSI0MTcyMTQ2Mjg2IiBzcmM9IkNOPXdzYWFob21vLCBPPUFGSVAsIEM9QVIsIFNFUklBTE5VTUJFUj1DVUlUIDMzNjkzNDUwMjM5IiBnZW5fdGltZT0iMTQ3NjE5MTkwNiIgZXhwX3RpbWU9IjE0NzYyMzUxNjYiIGRzdD0iQ049d3NmZSwgTz1BRklQLCBDPUFSIi8+CiAgICA8b3BlcmF0aW9uIHZhbHVlPSJncmFudGVkIiB0eXBlPSJsb2dpbiI+CiAgICAgICAgPGxvZ2luIHVpZD0iU0VSSUFMTlVNQkVSPUNVSVQgMjAzMzQ0Mjg4NzgsIENOPWVudmlvbGlicmUiIHNlcnZpY2U9IndzZmUiIHJlZ21ldGhvZD0iMjIiIGVudGl0eT0iMzM2OTM0NTAyMzkiIGF1dGhtZXRob2Q9ImNtcyI+CiAgICAgICAgICAgIDxyZWxhdGlvbnM+CiAgICAgICAgICAgICAgICA8cmVsYXRpb24gcmVsdHlwZT0iNCIga2V5PSIyMDMzNDQyODg3OCIvPgogICAgICAgICAgICA8L3JlbGF0aW9ucz4KICAgICAgICA8L2xvZ2luPgogICAgPC9vcGVyYXRpb24+Cjwvc3NvPgoK";
    private static String sign = "V/HI/0cvXRKrQsApt7gxLco9/RpGzU/lvMzmLKYF2t20TxObyv9hIy60z/f5fCxjCyhYcX8MQLT363LG2bHt/KwlbfNjLKQL4WrD3lYAC++QAvffpTI3B8UhSEDpYWe39vN1S2R8frnD0ufIeR1LVb0dZ647hgezuxl1eyy4cRY=";

    static String invoke_wsaa(byte[] LoginTicketRequest_xml_cms, String endpoint) throws Exception {

        String LoginTicketResponse = null;
        try {

            Service service = new Service();
            Call call = (Call) service.createCall();

            //
            // Prepare the call for the Web service
            //
            call.setTargetEndpointAddress(new java.net.URL(endpoint));
            call.setOperationName("loginCms");
            call.addParameter("request", XMLType.XSD_STRING, ParameterMode.IN);
            call.setReturnType(XMLType.XSD_STRING);

            //
            // Make the actual call and assign the answer to a String
            //
            LoginTicketResponse = (String) call.invoke(new Object[]{
                Base64.encode(LoginTicketRequest_xml_cms)});

        } catch (Exception e) {
            e.printStackTrace();
        }
        return (LoginTicketResponse);
    }

    //
    // Create the CMS Message
    //
    public static byte[] create_cms(String p12file, String p12pass, String signer, String dstDN, String service, Long TicketTime) {

        PrivateKey pKey = null;
        X509Certificate pCertificate = null;
        byte[] asn1_cms = null;
        CertStore cstore = null;
        String LoginTicketRequest_xml;
        String SignerDN = null;

        ArrayList<X509Certificate> certList = null;

        //
        // Manage Keys & Certificates
        //
        try {
            // Create a keystore using keys from the pkcs#12 p12file
            KeyStore ks = KeyStore.getInstance("pkcs12");
            FileInputStream p12stream = new FileInputStream(p12file);
            ks.load(p12stream, p12pass.toCharArray());
            p12stream.close();

            // Get Certificate & Private key from KeyStore
            pKey = (PrivateKey) ks.getKey(signer, p12pass.toCharArray());
            pCertificate = (X509Certificate) ks.getCertificate(signer);
            SignerDN = pCertificate.getSubjectDN().toString();

            // Create a list of Certificates to include in the final CMS
            certList = new ArrayList<X509Certificate>();
            certList.add(pCertificate);

            if (Security.getProvider("BC") == null) {
                Security.addProvider(new BouncyCastleProvider());
            }

            cstore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList), "BC");
        } catch (Exception e) {
            e.printStackTrace();
        }

        //
        // Create XML Message
        // 
        LoginTicketRequest_xml = create_LoginTicketRequest(SignerDN, dstDN, service, TicketTime);

        //
        // Create CMS Message
        //
        try {

            // Create a new empty CMS Message
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

            // Add a Signer to the Message
            gen.addSigner(pKey, pCertificate, CMSSignedDataGenerator.DIGEST_SHA1);

            // Add the Certificate to the Message
            gen.addCertificatesAndCRLs(cstore);

            // Add the data (XML) to the Message
            CMSProcessable data = new CMSProcessableByteArray(LoginTicketRequest_xml.getBytes());

            // Add a Sign of the Data to the Message
            CMSSignedData signed = gen.generate(data, true, "BC");

            // 
            asn1_cms = signed.getEncoded();

        } catch (Exception e) {
            e.printStackTrace();
        }

        return (asn1_cms);
    }

    //
    // Create XML Message for AFIP wsaa
    // 	
    public static String create_LoginTicketRequest(String SignerDN, String dstDN, String service, Long TicketTime) {

        String LoginTicketRequest_xml;

        Date GenTime = new Date();
        GregorianCalendar gentime = new GregorianCalendar();
        GregorianCalendar exptime = new GregorianCalendar();
        String UniqueId = new Long(GenTime.getTime() / 1000).toString();

        exptime.setTime(new Date(GenTime.getTime() + TicketTime));

        XMLGregorianCalendarImpl XMLGenTime = new XMLGregorianCalendarImpl(gentime);
        XMLGregorianCalendarImpl XMLExpTime = new XMLGregorianCalendarImpl(exptime);

        LoginTicketRequest_xml = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
                + "<loginTicketRequest version=\"1.0\">"
                + "<header>"
                + "<source>" + SignerDN + "</source>"
                + "<destination>" + dstDN + "</destination>"
                + "<uniqueId>" + UniqueId + "</uniqueId>"
                + "<generationTime>" + XMLGenTime + "</generationTime>"
                + "<expirationTime>" + XMLExpTime + "</expirationTime>"
                + "</header>"
                + "<service>" + service + "</service>"
                + "</loginTicketRequest>";

        //System.out.println("TRA: " + LoginTicketRequest_xml);
        return (LoginTicketRequest_xml);
    }

    private static String getXmlFEParamGetTiposCbte(String aCuit) {

        String FEParamGetTiposCbte_xml;

        FEParamGetTiposCbte_xml = "<soap12:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap12=\"http://www.w3.org/2003/05/soap-envelope\">"
                + "<soap12:Body>"
                + "<FEParamGetTiposCbte xmlns=\"http://ar.gov.afip.dif.FEV1/\">"
                + "<Auth>"
                + "<Token>" + token + "</Token>"
                + "<Sign>" + sign + "</Sign>"
                + "<Cuit>" + aCuit + "</Cuit>"
                + "</Auth>"
                + "</FEParamGetTiposCbte>"
                + "</soap12:Body>"
                + "</soap12:Envelope>";

        return (FEParamGetTiposCbte_xml);
    }

    //
    // Create the CMS Message
    //
    public static byte[] create_cmsTiposCompro(String p12file, String p12pass,
            String signer, String dstDN, String service, String cuit) {

        PrivateKey pKey = null;
        X509Certificate pCertificate = null;
        byte[] asn1_cms = null;
        CertStore cstore = null;
        String PedidoTiposComprobantes_xml;

        ArrayList<X509Certificate> certList = null;

        //
        // Manage Keys & Certificates
        //
        try {
            // Create a keystore using keys from the pkcs#12 p12file
            KeyStore ks = KeyStore.getInstance("pkcs12");
            FileInputStream p12stream = new FileInputStream(p12file);
            ks.load(p12stream, p12pass.toCharArray());
            p12stream.close();

            // Get Certificate & Private key from KeyStore
            pKey = (PrivateKey) ks.getKey(signer, p12pass.toCharArray());
            pCertificate = (X509Certificate) ks.getCertificate(signer);

            // Create a list of Certificates to include in the final CMS
            certList = new ArrayList<X509Certificate>();
            certList.add(pCertificate);

            if (Security.getProvider("BC") == null) {
                Security.addProvider(new BouncyCastleProvider());
            }

            cstore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList), "BC");
        } catch (Exception e) {
            e.printStackTrace();
        }

        //
        // Create XML Message
        // 
        PedidoTiposComprobantes_xml = getXmlFEParamGetTiposCbte(cuit);

        //
        // Create CMS Message
        //
        try {

            // Create a new empty CMS Message
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

            // Add a Signer to the Message
            gen.addSigner(pKey, pCertificate, CMSSignedDataGenerator.DIGEST_SHA1);

            // Add the Certificate to the Message
            gen.addCertificatesAndCRLs(cstore);

            // Add the data (XML) to the Message
            CMSProcessable data = new CMSProcessableByteArray(PedidoTiposComprobantes_xml.getBytes());

            // Add a Sign of the Data to the Message
            CMSSignedData signed = gen.generate(data, true, "BC");

            // 
            asn1_cms = signed.getEncoded();

        } catch (Exception e) {
            e.printStackTrace();
        }

        return (asn1_cms);
    }

    static String invoke_wsfe(byte[] PedidoComprobantes, String endpoint) throws Exception {

        String LoginTicketResponse = null;
        try {
            String cuit = "20334428878";

            String soapXml = getXmlFEParamGetTiposCbte(cuit);
            URL url = new URL("https://wswhomo.afip.gov.ar/wsfev1/service.asmx");
            URLConnection conn = url.openConnection();

// Set the necessary header fields
            conn.setRequestProperty("SOAPAction", "https://ar.gov.afip.dif.FEV1/FEParamGetTiposCbte");
            conn.setRequestProperty("Content-type", "application/soap+xml;charset=UTF-8;action=\"https://ar.gov.afip.dif.FEV1/FEParamGetTiposCbte\"");
            conn.setRequestProperty("Accept-Encoding", "gzip,deflate");
            conn.setDoOutput(true);
// Send the request
            OutputStreamWriter wr = new OutputStreamWriter(conn.getOutputStream());
            wr.write(soapXml);
            wr.flush();
// Read the response
            BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            String line;
//            while ((line = rd.readLine()) != null) {
//                System.out.println(line);
//                /*jEdit: print(line); */ }
            line = rd.readLine();

            XMLInputFactory xif = XMLInputFactory.newFactory();
            XMLStreamReader xsr = xif.createXMLStreamReader(new StringReader(line));
            xsr.nextTag(); // Advance to Envelope tag
            xsr.nextTag(); // Advance to Body tag
            xsr.nextTag(); // Advance to getNumberResponse tag
            System.out.println(xsr.getNamespaceContext().getNamespaceURI("ns"));

            JAXBContext jc = JAXBContext.newInstance(FEParamGetTiposCbteResponse.class);
            Unmarshaller unmarshaller = jc.createUnmarshaller();
            JAXBElement<FEParamGetTiposCbteResponse> je = unmarshaller.unmarshal(xsr, FEParamGetTiposCbteResponse.class);

            je.toString();
            FEParamGetTiposCbteResponse resp = je.getValue();

            resp.getFEParamGetTiposCbteResult();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return (LoginTicketResponse);
    }

    static String invoke_CAE() {
        String respuestaCAE = null;
        try {
            String cuit = "20334428878";

            String soapXml = generarXMLPedidoCAE();
            URL url = new URL("https://wswhomo.afip.gov.ar/wsfev1/service.asmx");
            URLConnection conn = url.openConnection();

// Set the necessary header fields
            conn.setRequestProperty("SOAPAction", "https://ar.gov.afip.dif.FEV1/FECAESolicitar");
            conn.setRequestProperty("Content-type", "application/soap+xml;charset=UTF-8;action=\"http://ar.gov.afip.dif.FEV1/FECAESolicitar\"");
            conn.setRequestProperty("Accept-Encoding", "gzip,deflate");
            conn.setDoOutput(true);
// Send the request
            OutputStreamWriter wr = new OutputStreamWriter(conn.getOutputStream());
            wr.write(soapXml);
            wr.flush();
// Read the response
            BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            String line;
//            while ((line = rd.readLine()) != null) {
//                System.out.println(line);
//                /*jEdit: print(line); */ }
            line = rd.readLine();

            XMLInputFactory xif = XMLInputFactory.newFactory();
            XMLStreamReader xsr = xif.createXMLStreamReader(new StringReader(line));
            xsr.nextTag(); // Advance to Envelope tag
            xsr.nextTag(); // Advance to Body tag
            xsr.nextTag(); // Advance to getNumberResponse tag

            JAXBContext jc = JAXBContext.newInstance(FECAESolicitarResponse.class);
            Unmarshaller unmarshaller = jc.createUnmarshaller();
            JAXBElement<FECAESolicitarResponse> je = unmarshaller.unmarshal(xsr, FECAESolicitarResponse.class);

            FECAESolicitarResponse resp = je.getValue();

            FECAEResponse fresp = resp.getFECAESolicitarResult();

            respuestaCAE = fresp.getFeDetResp().getFECAEDetResponse().get(0).getCAE();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return respuestaCAE;
    }

    private static String generarXMLPedido(String cuit) {
        String datos;
        datos = "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:ar=\"http://ar.gov.afip.dif.FEV1/\">"
                + "<soap:Header/>"
                + "<soap:Body>"
                + "<ar:FECAESolicitar>"
                + "<ar:Auth>"
                + "<ar:Token>" + token + "</ar:Token>"
                + "<ar:Sign>" + sign + "</ar:Sign>"
                + "<ar:Cuit>" + cuit + "</ar:Cuit>"
                + "</ar:Auth>"
                + "<ar:FeCAEReq>"
                + "<ar:FeCabReq>"
                + "<ar:CantReg>1</ar:CantReg>"
                + "<ar:PtoVta>12</ar:PtoVta>"
                + "<ar:CbteTipo>1</ar:CbteTipo>"
                + "</ar:FeCabReq>"
                + "<ar:FeDetReq>"
                + "<ar:FECAEDetRequest>"
                + "<ar:Concepto>1</ar:Concepto>"
                + "<ar:DocTipo>80</ar:DocTipo>"
                + "<ar:DocNro>20111111112</ar:DocNro>"
                + "<ar:CbteDesde>5</ar:CbteDesde>"
                + "<ar:CbteHasta>5</ar:CbteHasta>"
                + "<ar:CbteFch>20161007</ar:CbteFch>"
                + "<ar:ImpTotal>184.05</ar:ImpTotal>"
                + "<ar:ImpTotConc>0</ar:ImpTotConc>"
                + "<ar:ImpNeto>150</ar:ImpNeto>"
                + "<ar:ImpOpEx>0</ar:ImpOpEx>"
                + "<ar:ImpTrib>7.8</ar:ImpTrib>"
                + "<ar:ImpIVA>26.25</ar:ImpIVA>"
                + "<ar:FchServDesde></ar:FchServDesde>"
                + "<ar:FchServHasta></ar:FchServHasta>"
                + "<ar:FchVtoPago></ar:FchVtoPago>"
                + "<ar:MonId>PES</ar:MonId>"
                + "<ar:MonCotiz>1</ar:MonCotiz>"
                + "<ar:Tributos>"
                + "<ar:Tributo>"
                + "<ar:Id>99</ar:Id>"
                + "<ar:Desc>Impuesto Municipal Matanza</ar:Desc>"
                + "<ar:BaseImp>150</ar:BaseImp>"
                + "<ar:Alic>5.2</ar:Alic>"
                + "<ar:Importe>7.8</ar:Importe>"
                + "</ar:Tributo>"
                + "</ar:Tributos>"
                + "<ar:Iva>"
                + "<ar:AlicIva>"
                + "<ar:Id>5</ar:Id>"
                + "<ar:BaseImp>100</ar:BaseImp>"
                + "<ar:Importe>21</ar:Importe>"
                + "</ar:AlicIva>"
                + "<ar:AlicIva>"
                + "<ar:Id>4</ar:Id>"
                + "<ar:BaseImp>50</ar:BaseImp>"
                + "<ar:Importe>5.25</ar:Importe>"
                + "</ar:AlicIva>"
                + "</ar:Iva>"
                + "</ar:FECAEDetRequest>"
                + "</ar:FeDetReq>"
                + "</ar:FeCAEReq>"
                + "</ar:FECAESolicitar>"
                + "</soap:Body>"
                + "</soap:Envelope>";
        return (datos);
    }

    public static String generarXMLPedidoCAE() throws PropertyException, JAXBException {
        FECAESolicitar req = new FECAESolicitar();
        FECAERequest feCAEReq = new FECAERequest();
        FEAuthRequest auth = new FEAuthRequest();

        FECAECabRequest cabReq = new FECAECabRequest();

        ArrayOfFECAEDetRequest array = new ArrayOfFECAEDetRequest();

        FECAEDetRequest detail1 = new FECAEDetRequest();
        FECAEDetRequest detail2 = new FECAEDetRequest();

        // Configuracion de autorizacion
        auth.setCuit(20334428878l);
        auth.setToken(token);
        auth.setSign(sign);
        req.setAuth(auth);

        // Configuracion de cabecera de pedido
        cabReq.setCbteTipo(6);
        cabReq.setPtoVta(12);
        cabReq.setCantReg(1);
        feCAEReq.setFeCabReq(cabReq);

        // Configuracion de un item de detalle
        detail1.setConcepto(2);
        detail1.setDocTipo(86);
        detail1.setDocNro(20111111112l);
        detail1.setCbteDesde(2);
        detail1.setCbteHasta(2);
        detail1.setImpTotal(121);
        detail1.setImpTotConc(0);
        detail1.setImpNeto(100);
        detail1.setImpOpEx(0);
        detail1.setImpIVA(21);
        detail1.setImpTrib(0);
        detail1.setMonId("PES");
        detail1.setMonCotiz(1);
        detail1.setCbteFch("20161011");
        detail1.setFchServDesde("20161004");
        detail1.setFchServHasta("20161005");
        detail1.setFchVtoPago("20161015");
        ArrayOfAlicIva listIva = new ArrayOfAlicIva();
        AlicIva iva = new AlicIva();
        iva.setBaseImp(100);
        iva.setId(5);
        iva.setImporte(21);
        listIva.getAlicIva().add(iva);
        detail1.setIva(listIva);

        array.getFECAEDetRequest().add(detail1);
        feCAEReq.setFeDetReq(array);

        req.setFeCAEReq(feCAEReq);

        JAXBContext jaxbContext = JAXBContext.newInstance(FECAESolicitar.class);
        Marshaller jaxbMarshaller = jaxbContext.createMarshaller();

// output pretty printed
        jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

        StringWriter sw = new StringWriter();
        jaxbMarshaller.marshal(req, sw);
        jaxbMarshaller.marshal(req, System.out);
        String xmlString = sw.toString();

        String nuevoEncabezado = "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:ar=\"http://ar.gov.afip.dif.FEV1/\"><soap:Header/><soap:Body>";
        String exEncabezado = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>";
        String pedido = xmlString.replace(exEncabezado, nuevoEncabezado);

        return pedido + "</soap:Body></soap:Envelope>";
    }

    static int invokeGetUltimoComprobante() {
        int ultComprobante = 0;
        try {
            String cuit = "20334428878";

//            String soapXml = generarXMLUltimoComprobante(cuit);
            String soapXml = generarXMLUltimoComprobanteClases();
            URL url = new URL("https://wswhomo.afip.gov.ar/wsfev1/service.asmx");
            URLConnection conn = url.openConnection();

// Set the necessary header fields
            conn.setRequestProperty("SOAPAction", "http://ar.gov.afip.dif.FEV1/FECompUltimoAutorizado");
            conn.setRequestProperty("Content-type", "application/soap+xml;charset=UTF-8;action=\"http://ar.gov.afip.dif.FEV1/FECompUltimoAutorizado");
            conn.setRequestProperty("Accept-Encoding", "gzip,deflate");
            conn.setDoOutput(true);
// Send the request
            OutputStreamWriter wr = new OutputStreamWriter(conn.getOutputStream());
            wr.write(soapXml);
            wr.flush();
// Read the response
            BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            String line;
//            while ((line = rd.readLine()) != null) {
//                System.out.println(line);
//                /*jEdit: print(line); */ }
            line = rd.readLine();

            XMLInputFactory xif = XMLInputFactory.newFactory();
            XMLStreamReader xsr = xif.createXMLStreamReader(new StringReader(line));
            xsr.nextTag(); // Advance to Envelope tag
            xsr.nextTag(); // Advance to Body tag
            xsr.nextTag(); // Advance to getNumberResponse tag

            JAXBContext jc = JAXBContext.newInstance(FECompUltimoAutorizadoResponse.class);
            Unmarshaller unmarshaller = jc.createUnmarshaller();
            JAXBElement<FECompUltimoAutorizadoResponse> je = unmarshaller.unmarshal(xsr, FECompUltimoAutorizadoResponse.class);

            FECompUltimoAutorizadoResponse resp = je.getValue();

            FERecuperaLastCbteResponse fresp = resp.getFECompUltimoAutorizadoResult();

            ultComprobante = fresp.getCbteNro();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return ultComprobante;
    }

    private static String generarXMLUltimoComprobante(String cuit) {
        String datos;
        datos = "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:ar=\"http://ar.gov.afip.dif.FEV1/\">"
                + "<soap:Header/>"
                + "<soap:Body>"
                + "<ar:FECompUltimoAutorizado>"
                + "<ar:Auth>"
                + "<ar:Token>" + token + "</ar:Token>"
                + "<ar:Sign>" + sign + "</ar:Sign>"
                + "<ar:Cuit>" + cuit + "</ar:Cuit>"
                + "</ar:Auth>"
                + "<ar:PtoVta>12</ar:PtoVta>"
                + "<ar:CbteTipo>1</ar:CbteTipo>"
                + "</ar:FECompUltimoAutorizado>"
                + "</soap:Body>"
                + "</soap:Envelope>";
        return datos;
    }

    public static String generarXMLUltimoComprobanteClases() throws JAXBException {
        FECompUltimoAutorizado req = new FECompUltimoAutorizado();
        FEAuthRequest auth = new FEAuthRequest();
        // Configuracion de autorizacion
        auth.setCuit(20334428878l);
        auth.setToken(token);
        auth.setSign(sign);
        req.setAuth(auth);

        req.setCbteTipo(6);
        req.setPtoVta(12);

        JAXBContext jaxbContext = JAXBContext.newInstance(FECompUltimoAutorizado.class);
        Marshaller jaxbMarshaller = jaxbContext.createMarshaller();

        // output pretty printed
        jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

        StringWriter sw = new StringWriter();
        jaxbMarshaller.marshal(req, sw);
        String xmlString = sw.toString();
        
        String nuevoEncabezado = "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:ar=\"http://ar.gov.afip.dif.FEV1/\"><soap:Header/><soap:Body>";
        String exEncabezado = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>";
        String pedido = xmlString.replace(exEncabezado, nuevoEncabezado);

        return pedido + "</soap:Body></soap:Envelope>";
    }
}
