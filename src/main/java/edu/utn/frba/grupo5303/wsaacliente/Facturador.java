/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.utn.frba.grupo5303.wsaacliente;

import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;

/**
 *
 * @author flavio
 */
public class Facturador {

    private String token = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9InllcyI/Pgo8c3NvIHZlcnNpb249IjIuMCI+CiAgICA8aWQgdW5pcXVlX2lkPSIxNTU4ODk5MjUiIHNyYz0iQ049d3NhYWhvbW8sIE89QUZJUCwgQz1BUiwgU0VSSUFMTlVNQkVSPUNVSVQgMzM2OTM0NTAyMzkiIGdlbl90aW1lPSIxNDc1NjgzOTQ4IiBleHBfdGltZT0iMTQ3NTcyNzIwOCIgZHN0PSJDTj13c2ZlLCBPPUFGSVAsIEM9QVIiLz4KICAgIDxvcGVyYXRpb24gdmFsdWU9ImdyYW50ZWQiIHR5cGU9ImxvZ2luIj4KICAgICAgICA8bG9naW4gdWlkPSJTRVJJQUxOVU1CRVI9Q1VJVCAyMDMzNDQyODg3OCwgQ049ZW52aW9saWJyZSIgc2VydmljZT0id3NmZSIgcmVnbWV0aG9kPSIyMiIgZW50aXR5PSIzMzY5MzQ1MDIzOSIgYXV0aG1ldGhvZD0iY21zIj4KICAgICAgICAgICAgPHJlbGF0aW9ucz4KICAgICAgICAgICAgICAgIDxyZWxhdGlvbiByZWx0eXBlPSI0IiBrZXk9IjIwMzM0NDI4ODc4Ii8+CiAgICAgICAgICAgIDwvcmVsYXRpb25zPgogICAgICAgIDwvbG9naW4+CiAgICA8L29wZXJhdGlvbj4KPC9zc28+Cgo=";
    private String sign = "Mjck9/998qD39IbPn+E6LD30lQZ+Iy7E7mScHejrg8k8n7SmK1iUUtL0q7dC+zkj0QF6Iud7YShhqJ2CkbiAtNm0J3J21kwpEzlfFJBd2yv9W+ObaqmAfImQjzmQCwtPol3km0q0Tko7GE5ZuXo4Ch4uOF2AxYSlxVSZtOh0GhA=";

    public Facturador() {
    }

    public Facturador(String token, String sign) {
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

    public String solicitarFECAE() {
        String pedido = generarXMLPedido();
        
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
    }

    public String generarXMLPedido() {
        return "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:ar=\"http://ar.gov.afip.dif.FEV1/\">"
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
