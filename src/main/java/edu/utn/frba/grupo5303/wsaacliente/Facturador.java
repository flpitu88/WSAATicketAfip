/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.utn.frba.grupo5303.wsaacliente;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import javax.xml.rpc.ParameterMode;
import javax.xml.rpc.ServiceException;
import org.apache.axis.client.Call;
import org.apache.axis.client.Service;
import org.apache.axis.encoding.Base64;
import org.apache.axis.encoding.XMLType;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author flavio
 */
public class Facturador {
    
    private String token;
    private String sign;
    private String p12file;
    private String p12pass;
    private String signer;
    private String dstDN;
    private String service;
    
    public Facturador() {
    }
    
    public Facturador(String token, String sign, String p12file, String p12pass, String signer,
            String dstDN, String service) {
        this.p12file = p12file;
        this.p12pass = p12pass;
        this.signer = signer;
        this.dstDN = dstDN;
        this.service = service;
        this.token = token;
        this.sign = sign;
    }
    
    public String getToken() {
        return token;
    }
    
    public void setToken(String token) {
        this.token = token;
    }
    
    public String getSign() {
        return sign;
    }
    
    public void setSign(String sign) {
        this.sign = sign;
    }
    
    public String getP12file() {
        return p12file;
    }
    
    public void setP12file(String p12file) {
        this.p12file = p12file;
    }
    
    public String getP12pass() {
        return p12pass;
    }
    
    public void setP12pass(String p12pass) {
        this.p12pass = p12pass;
    }
    
    public String getSigner() {
        return signer;
    }
    
    public void setSigner(String signer) {
        this.signer = signer;
    }
    
    public String getDstDN() {
        return dstDN;
    }
    
    public void setDstDN(String dstDN) {
        this.dstDN = dstDN;
    }
    
    public String getService() {
        return service;
    }
    
    public void setService(String service) {
        this.service = service;
    }
    
    public String solicitarFECAE() throws CertStoreException, CMSException, NoSuchAlgorithmException, NoSuchProviderException, IOException, ServiceException {
        PrivateKey pKey = null;
        X509Certificate pCertificate = null;
        byte[] asn1_cms = null;
        CertStore cstore = null;
        
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
        
        String pedido = generarXMLPedido();

        // Create a new empty CMS Message
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        // Add a Signer to the Message
        gen.addSigner(pKey, pCertificate, CMSSignedDataGenerator.DIGEST_SHA1);

        // Add the Certificate to the Message
        gen.addCertificatesAndCRLs(cstore);

        // Add the data (XML) to the Message
        CMSProcessable data = new CMSProcessableByteArray(pedido.getBytes());
        
//        FECAESolicitar sol = new FECAESolicitar();
//        sol.setAuth(new FEAuthRequest());
//        sol.setFeCAEReq(new FECAERequest());        

        // Add a Sign of the Data to the Message
        CMSSignedData signed = gen.generate(data, true, "BC");

        // 
        asn1_cms = signed.getEncoded();
        
        Service service = new Service();
        Call call = (Call) service.createCall();

        //
        // Prepare the call for the Web service
        //
        call.setTargetEndpointAddress(new java.net.URL("https://wswhomo.afip.gov.ar/wsfev1/service.asmx"));
        call.setOperationName("FECAESolicitar");
        call.addParameter("request", XMLType.XSD_STRING, ParameterMode.IN);
        call.setReturnType(XMLType.XSD_STRING);

        //
        // Make the actual call and assign the answer to a String
        //
        String response = (String) call.invoke(new Object[]{
            Base64.encode(asn1_cms)});
        
        return response;
    }
    
    public String generarXMLPedido() {
        return "<soap:Envelope xmlns:soap=”http://www.w3.org/2003/05/soap-envelope\" xmlns:ar=”http://ar.gov.afip.dif.fev1/”>"
                + "<soapenv:Header/>"
                + "<soapenv:Body>"
                + "<ar:FECAESolicitar>"
                + "<ar:Auth>"
                + "<ar:Token>" + token + "</ar:Token>"
                + "<ar:Sign>" + sign + "</ar:Sign>"
                + "<ar:Cuit>33693450239</ar:Cuit>"
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
                + "<ar:CbteDesde>1</ar:CbteDesde>"
                + "<ar:CbteHasta>1</ar:CbteHasta>"
                + "<ar:CbteFch>20100903</ar:CbteFch>"
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
                + "</soapenv:Body>"
                + "</soapenv:Envelope>";
    }
    
}
