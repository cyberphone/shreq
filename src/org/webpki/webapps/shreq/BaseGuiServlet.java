/*
 *  Copyright 2006-2019 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.webapps.shreq;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

import java.util.GregorianCalendar;
import java.util.LinkedHashMap;

import java.util.logging.Logger;

import java.util.regex.Pattern;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;

import org.webpki.jose.JOSEAsymKeyHolder;
import org.webpki.jose.JOSESupport;

import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;

import org.webpki.shreq.SHREQSupport;

import org.webpki.util.Base64;

public class BaseGuiServlet extends HttpServlet {

    static Logger logger = Logger.getLogger(BaseGuiServlet.class.getName());

    private static final long serialVersionUID = 1L;

    // HTML form arguments
    static final String TARGET_URI         = "uri";
    
    static final String REQUEST_TYPE       = "reqtyp";  // True = JSON else URI

    static final String JSON_PAYLOAD       = "json";

    static final String JWS_VALIDATION_KEY = "vkey";
    
    static final String PRM_HTTP_METHOD    = "mtd";

    static final String TXT_OPT_HEADERS    = "hdrs";

    static final String TXT_JWS_EXTRA      = "xtra";

    static final String TXT_SECRET_KEY     = "sec";

    static final String TXT_PRIVATE_KEY    = "priv";

    static final String TXT_CERT_PATH      = "cert";

    static final String PRM_JWS_ALGORITHM  = "alg";

    static final String FLG_CERT_PATH      = "cerflg";
    static final String FLG_JWK_INLINE     = "jwkflg";
    static final String FLG_DEF_METHOD     = "defmtd";
    static final String FLG_IAT_PRESENT    = "iatflg";
    static final String FLG_HEADERS        = "hdrflg";
    
    static final String DEFAULT_ALGORITHM   = "ES256";
    static final String DEFAULT_JSON_METHOD = "POST";
    static final String DEFAULT_URI_METHOD  = "GET";
    
    static class SelectMethod {

        StringBuilder html = new StringBuilder("<select name=\"" +
                PRM_HTTP_METHOD + "\" id=\"" + PRM_HTTP_METHOD + "\">");
        
        SelectMethod() {
            for (String method : SHREQSupport.HTTP_METHODS) {
                html.append("<option value=\"")
                    .append(method)
                    .append("\"")
                    .append(method.equals("POST") ? " selected>" : ">")
                    .append(method)
                    .append("</option>");
            }
        }

        @Override
        public String toString() {
            return html.append("</select>").toString();
        }
    }

    class SelectAlg {

        String preSelected;
        StringBuilder html = new StringBuilder("<select name=\"" +
                PRM_JWS_ALGORITHM + "\" id=\"" +
                PRM_JWS_ALGORITHM + "\" onchange=\"algChange(this.value)\">");
        
        SelectAlg(String preSelected) {
            this.preSelected = preSelected;
        }

        SelectAlg add(SignatureAlgorithms algorithm) throws IOException {
            String algId = algorithm.getAlgorithmId(AlgorithmPreferences.JOSE);
            html.append("<option value=\"")
                .append(algId)
                .append("\"")
                .append(algId.equals(preSelected) ? " selected>" : ">")
                .append(algId)
                .append("</option>");
            return this;
        }

        @Override
        public String toString() {
            return html.append("</select>").toString();
        }
    }
    
    StringBuilder checkBox(String idName, String text, boolean checked, String onchange) {
        StringBuilder html = new StringBuilder("<div style=\"display:flex;align-items:center\"><input type=\"checkbox\" id=\"")
            .append(idName)
            .append("\" name=\"")
            .append(idName)
            .append("\"");
        if (checked) {
            html.append(" checked");
        }
        if (onchange != null) {
            html.append(" onchange=\"")
                .append(onchange)
                .append("\"");
        }
        html.append("><div style=\"display:inline-block\">")
            .append(text)
            .append("</div></div>");
        return html;
    }

    StringBuilder radioButton(String name, String text, String value, boolean checked, String onchange) {
        StringBuilder html = new StringBuilder("<div style=\"display:flex;align-items:center\"><input type=\"radio\" name=\"")
            .append(name)
            .append("\" value=\"")
            .append(value)
            .append("\"");
        if (checked) {
            html.append(" checked");
        }
        if (onchange != null) {
            html.append(" onchange=\"")
                .append(onchange)
                .append("\"");
        }
        html.append("><div style=\"display:inline-block\">")
            .append(text)
            .append("</div></div>");
        return html;
    }
    
    StringBuilder parameterBox(String header, StringBuilder body) {
        return new StringBuilder(
            "<div style=\"display:flex;justify-content:center;margin-top:20pt\">" +
              "<div class=\"sigparmbox\">" +
                "<div style=\"display:flex;justify-content:center\">" +
                  "<div class=\"sigparmhead\">")
        .append(header)
        .append(
                  "</div>" +
                "</div>")
        .append(body)
        .append(
              "</div>" +
            "</div>");      
    }

    StringBuilder getRequestParameters() {
        return parameterBox("Request Parameters", 
            new StringBuilder()
            .append(
                "<div style=\"display:flex;align-items:center\">")
                .append(new SelectMethod().toString())
           .append(
               "<div style=\"display:inline-block;padding:0 10pt 0 5pt\">HTTP Method</div>" +
               "<div class=\"defbtn\" onclick=\"restoreRequestDefaults()\">Restore&nbsp;defaults</div></div>")
           .append(radioButton(REQUEST_TYPE, "JSON based request", "true", true, "requestChange(true)"))
           .append(radioButton(REQUEST_TYPE, "URI based request", "false", false, "requestChange(false)"))
           .append(checkBox(FLG_HEADERS, "Include HTTP headers as well", 
                                 false, "headerFlagChange(this.checked)")));
    }

    String getParameter(HttpServletRequest request, String parameter) throws IOException {
        String string = request.getParameter(parameter);
        if (string == null) {
            throw new IOException("Missing data for: "+ parameter);
        }
        return string.trim();
    }
    
    byte[] getBinaryParameter(HttpServletRequest request, String parameter) throws IOException {
        return getParameter(request, parameter).getBytes("utf-8");
    }

    String getTextArea(HttpServletRequest request, String name) throws IOException {
        String string = getParameter(request, name);
        StringBuilder s = new StringBuilder();
        for (char c : string.toCharArray()) {
            if (c != '\r') {
                s.append(c);
            }
        }
        return s.toString();
    }
    private static final String HEADER_SYNTAX = "[ \t]*[a-z0-9A-Z\\$\\._\\-]+[ \t]*:.*";
    
    static final Pattern HEADER_STRING_ARRAY_SYNTAX = 
            Pattern.compile(HEADER_SYNTAX + "+(\n" + HEADER_SYNTAX + "+)*");
    
    LinkedHashMap<String,String> createHeaderData(String rawText) throws IOException {
        LinkedHashMap<String,String> headerData = new LinkedHashMap<String,String>();
        if (!rawText.isEmpty()) {
            rawText = rawText.trim().replace("\r", "");
            if (!HEADER_STRING_ARRAY_SYNTAX.matcher(rawText).matches()) {
                throw new IOException("HTTP Header syntax");
            }
            for (String headerLine : rawText.split("\n")) {
                int colon = headerLine.indexOf(':');
                String headerName = headerLine.substring(0, colon).trim().toLowerCase();
                if (headerData.put(headerName, headerLine.substring(colon + 1)) != null) {
                    throw new IOException("Duplicate header: " + headerName);
                }
            }
        }
        return headerData;
    }
    
    static String getPEMFromPublicKey(PublicKey publicKey) {
        return  "-----BEGIN PUBLIC KEY-----\n" +
                new Base64().getBase64StringFromBinary(publicKey.getEncoded()) +
                "\n-----END PUBLIC KEY-----";
    }

    private static final String TEST_MESSAGE = 
            "{\n" +
            "  \"statement\": \"Hello signed world!\",\n" +
            "  \"otherProperties\": [2e+3, true]\n" +
            "}";

    // The ! doesn't work great in bash...
    private static final String CURL_TEST_MESSAGE = 
            "{\n" +
            "  \"name\": \"Jane Smith\",\n" +
            "  \"profession\": \"hacker\"\n" +
            "}";

    static String sampleJson_JS;

    static String sampleJsonRequest_JS;
    
    static String sampleJsonRequest_CURL;

    static String sampleJsonRequestUri;

    static String sampleUriRequestUri;
    
    static String sampleUriRequestUri2BeSigned;

    protected void getSampleData(HttpServletRequest request) throws IOException {
        if (sampleJsonRequest_JS == null) {
            synchronized(this) {
                try {
                    String baseUri = 
                            SHREQSupport.normalizeTargetURI(BaseRequestServlet.getUrlFromRequest(request));
                    sampleJsonRequestUri = 
                            baseUri.substring(0, baseUri.indexOf("/shreq/") + 6) +
                            BaseRequestServlet.PRECONFREQ;
                    sampleUriRequestUri2BeSigned = sampleJsonRequestUri + "/456";

                    LinkedHashMap<String,String> noHeaders = new LinkedHashMap<String,String>();

                    AsymSignatureAlgorithms signatureAlgorithm = AsymSignatureAlgorithms.ECDSA_SHA256;

                    // Sign it using the provided algorithm and key
                    PrivateKey privateKey = 
                            SHREQService.predefinedKeyPairs
                                .get(signatureAlgorithm
                                        .getAlgorithmId(AlgorithmPreferences.JOSE)).getPrivate();

                    JSONObjectWriter JWS_Protected_Header =
                            JOSESupport.setSignatureAlgorithm(new JSONObjectWriter(), 
                                                              signatureAlgorithm);
                    JSONObjectWriter message = 
                            new JSONObjectWriter(JSONParser.parse(TEST_MESSAGE));
                    
                    JSONObjectWriter secinf = 
                            SHREQSupport.createJSONRequestSecInf(sampleJsonRequestUri,
                                                                 null,
                                                                 new GregorianCalendar(),
                                                                 noHeaders,
                                                                 signatureAlgorithm);
                    message.setObject(SHREQSupport.SHREQ_SECINF_LABEL, secinf);
                    byte[] JWS_Payload = message.serializeToBytes(JSONOutputFormats.CANONICALIZED);
        
                    String jwsString = 
                            JOSESupport.createJwsSignature(JWS_Protected_Header, 
                                                           JWS_Payload,
                                                           new JOSEAsymKeyHolder(privateKey),
                                                           true);
                    // Create the completed object which now is in "writer"
                    secinf.setString(SHREQSupport.SHREQ_JWS_STRING, jwsString);
                    
                    sampleJsonRequest_JS =
                            HTML.javaScript(message.serializeToString(JSONOutputFormats.PRETTY_PRINT));

                    message = new JSONObjectWriter(JSONParser.parse(CURL_TEST_MESSAGE));
                    
                    secinf = SHREQSupport.createJSONRequestSecInf(sampleJsonRequestUri,
                                                                  null,
                                                                  new GregorianCalendar(),
                                                                  noHeaders,
                                                                  signatureAlgorithm);
                    message.setObject(SHREQSupport.SHREQ_SECINF_LABEL, secinf);
                    JWS_Payload = message.serializeToBytes(JSONOutputFormats.CANONICALIZED);

                    jwsString = 
                            JOSESupport.createJwsSignature(JWS_Protected_Header, 
                                                           JWS_Payload,
                                                           new JOSEAsymKeyHolder(privateKey),
                                                           true);
                    // Create the completed object which now is in "writer"
                    secinf.setString(SHREQSupport.SHREQ_JWS_STRING, jwsString);

                    sampleJsonRequest_CURL =
                            message.serializeToString(JSONOutputFormats.NORMALIZED).replace("\"", "\\\"");

                    secinf = SHREQSupport.createURIRequestSecInf(sampleUriRequestUri2BeSigned,
                                                                 null,
                                                                 new GregorianCalendar(),
                                                                 noHeaders,
                                                                 signatureAlgorithm);
                    sampleUriRequestUri = SHREQSupport.addJwsToTargetUri(
                            sampleUriRequestUri2BeSigned,
                            JOSESupport.createJwsSignature(
                                    JWS_Protected_Header, 
                                    secinf.serializeToBytes(JSONOutputFormats.NORMALIZED),
                                    new JOSEAsymKeyHolder(privateKey),
                                    false));

                    sampleJson_JS = HTML.javaScript(TEST_MESSAGE);

                } catch (GeneralSecurityException e) {
                    sampleJsonRequest_JS = "Internal error - Call admin";
                }
            }
        }
    }
}
