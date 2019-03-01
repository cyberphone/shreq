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

import java.net.URLEncoder;

import java.security.KeyPair;

import java.util.GregorianCalendar;

import java.util.logging.Logger;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.MACAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;

import org.webpki.jose.JOSEAsymKeyHolder;
import org.webpki.jose.JOSESupport;
import org.webpki.jose.JOSESymKeyHolder;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;

import org.webpki.shreq.SHREQSupport;

import org.webpki.util.Base64;
import org.webpki.util.DebugFormatter;
import org.webpki.util.PEMDecoder;

public class CreateServlet extends HttpServlet {
    
    static Logger logger = Logger.getLogger(CreateServlet.class.getName());

    private static final long serialVersionUID = 1L;

    // HTML form arguments
    static final String PRM_URI          = "uri";

    static final String PRM_JSON_DATA    = "json";
    
    static final String PRM_JWS_EXTRA    = "xtra";

    static final String PRM_SECRET_KEY   = "sec";

    static final String PRM_PRIVATE_KEY  = "priv";

    static final String PRM_CERT_PATH    = "cert";

    static final String PRM_ALGORITHM    = "alg";

    static final String PRM_METHOD       = "mtd";
    static final String PRM_SCHEME       = "scheme";

    static final String FLG_CERT_PATH    = "cerflg";
    static final String FLG_JWK_INLINE   = "jwkflg";
    static final String FLG_IAT_PRESENT  = "iatflg";
    
    static final String DEFAULT_ALGORITHM   = "ES256";
    static final String DEFAULT_JSON_METHOD = "POST";
    static final String DEFAULT_URI_METHOD  = "GET";
    
    static final String TEST_MESSAGE = 
            "{\n" +
            "  \"statement\": \"Hello signed world!\",\n" +
            "  \"otherProperties\": [2e+3, true]\n" +
            "}";
    
    static String _defaultTargetUri;
    
    static String getDefaultUri(HttpServletRequest request) {
        if (_defaultTargetUri == null) {
            synchronized(CreateServlet.class) {
                String url = BaseRequestServlet.getUrlFromRequest(request);
                _defaultTargetUri = url.substring(0, url.indexOf("/shreq/") + 6) +
                        HomeServlet.PRECONFREQ + "?id=456";
            }
        }
        return _defaultTargetUri;
    }
    
    static final String[] METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "CONNECT"};
    
    static class SelectMethod {

        StringBuilder html = new StringBuilder("<select name=\"" +
                PRM_METHOD + "\" id=\"" + PRM_METHOD + "\">");
        
        SelectMethod() {
            for (String method : METHODS) {
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
                PRM_ALGORITHM + "\" id=\"" +
                PRM_ALGORITHM + "\" onchange=\"algChange(this.value)\">");
        
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
    
    static StringBuilder parameterBox(String header, StringBuilder body) {
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

    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        String targetUri = getDefaultUri(request);
        String selected = "ES256";
        StringBuilder js = new StringBuilder("\"use strict\";\n")
            .append(SHREQService.keyDeclarations);
        StringBuilder html = new StringBuilder(
                "<form name=\"shoot\" method=\"POST\" action=\"create\">" +
                "<div class=\"header\">SHREQ Message Creation</div>")
            .append(
                HTML.fancyText(
                        true,
                        PRM_URI,
                        1,
                        "",
                        "Target URI"))

            .append(
                HTML.fancyText(
                        true,
                        PRM_JSON_DATA,
                        10,
                        "",
                        "Paste an unsigned JSON object in the text box or try with the default"))

            .append(parameterBox("Request Parameters", 
                new StringBuilder()
                .append(
                    "<div style=\"display:flex;align-items:center\">")
                    .append(new SelectMethod().toString())
               .append(
                   "<div style=\"display:inline-block;padding:0 10pt 0 5pt\">HTTP Method</div>" +
                   "<div class=\"defbtn\" onclick=\"restoreRequestDefaults()\">Restore&nbsp;defaults</div></div>")
               .append(radioButton(PRM_SCHEME, "JSON based request", "true", true, "requestChange(true)"))
               .append(radioButton(PRM_SCHEME, "URI based request", "false", false, "requestChange(false)"))))

            .append(parameterBox("Security Parameters",
                new StringBuilder()
                .append(
                   "<div style=\"display:flex;align-items:center\">")
                .append(new SelectAlg(selected)
                     .add(MACAlgorithms.HMAC_SHA256)
                     .add(MACAlgorithms.HMAC_SHA384)
                     .add(MACAlgorithms.HMAC_SHA512)
                     .add(AsymSignatureAlgorithms.ECDSA_SHA256)
                     .add(AsymSignatureAlgorithms.ECDSA_SHA384)
                     .add(AsymSignatureAlgorithms.ECDSA_SHA512)
                     .add(AsymSignatureAlgorithms.RSA_SHA256)
                     .add(AsymSignatureAlgorithms.RSA_SHA384)
                     .add(AsymSignatureAlgorithms.RSA_SHA512)
                     .toString())
                .append(
                    "<div style=\"display:inline-block;padding:0 10pt 0 5pt\">Algorithm</div>" +
                    "<div class=\"defbtn\" onclick=\"restoreSecurityDefaults()\">Restore&nbsp;defaults</div></div>")
                .append(checkBox(FLG_JWK_INLINE, "Automagically insert public key (JWK)", 
                                 false, "jwkFlagChange(this.checked)"))
                .append(checkBox(FLG_CERT_PATH, "Include provided certificate path (X5C)", 
                                 false, "certFlagChange(this.checked)"))
                .append(checkBox(FLG_IAT_PRESENT, "Include time stamp (IAT)", 
                                 true, null))))
            .append(
                "<div style=\"display:flex;justify-content:center\">" +
                "<div class=\"stdbtn\" onclick=\"document.forms.shoot.submit()\">" +
                "Create Signed Request" +
                "</div>" +
                "</div>")
            .append(
                HTML.fancyText(true,
                          PRM_JWS_EXTRA,
                          4,
                          "",
                          "Additional JWS header parameters (here expressed as properties of a JSON object)"))
            .append(
                HTML.fancyText(false,
                          PRM_SECRET_KEY,
                          1,
                          "",
                          "Secret key in hexadecimal format"))
            .append(
                HTML.fancyText(false,
                          PRM_PRIVATE_KEY,
                          4,
                          "",
                          "Private key in PEM/PKCS #8 or &quot;plain&quot; JWK format"))
            .append(
                HTML.fancyText(false,
                          PRM_CERT_PATH,
                          4,
                          "",
                          "Certificate path in PEM format"))
            .append(
                "</form>" +
                "<div>&nbsp;</div>");
        js.append(
            "function fill(id, alg, keyHolder, unconditionally) {\n" +
            "  let element = document.getElementById(id).children[1];\n" +
            "  if (unconditionally || element.value == '') element.value = keyHolder[alg];\n" +
            "}\n" +
            "function disableAndClearCheckBox(id) {\n" +
            "  let checkBox = document.getElementById(id);\n" +
            "  checkBox.checked = false;\n" +
            "  checkBox.disabled = true;\n" +
            "}\n" +
            "function enableCheckBox(id) {\n" +
            "  document.getElementById(id).disabled = false;\n" +
            "}\n" +
            "function setUserData(unconditionally) {\n" +
            "  let element = document.getElementById('" + PRM_JSON_DATA + "').children[1];\n" +
            "  if (unconditionally || element.value == '') element.value = '")
          .append(HTML.javaScript(TEST_MESSAGE))
          .append("';\n" +
            "  element = document.getElementById('" + PRM_JWS_EXTRA + "').children[1];\n" +
            "  if (unconditionally || element.value == '') element.value = '{\\n}';\n" +
            "  element = document.getElementById('" + PRM_URI + "').children[1];\n" +
            "  if (unconditionally || element.value == '') element.value = '")
         .append(targetUri)
         .append("';\n" +
            "}\n" +
            "function setParameters(alg, unconditionally) {\n" +
            "  if (alg.startsWith('HS')) {\n" +
            "    showCert(false);\n" +
            "    showPriv(false);\n" +
            "    disableAndClearCheckBox('" + FLG_CERT_PATH + "');\n" +
            "    disableAndClearCheckBox('" + FLG_JWK_INLINE + "');\n" +
            "    fill('" + PRM_SECRET_KEY + "', alg, " + 
                 SHREQService.KeyDeclaration.SECRET_KEYS + ", unconditionally);\n" +
            "    showSec(true)\n" +
            "  } else {\n" +
            "    showSec(false)\n" +
            "    enableCheckBox('" + FLG_CERT_PATH + "');\n" +
            "    enableCheckBox('" + FLG_JWK_INLINE + "');\n" +
            "    fill('" + PRM_PRIVATE_KEY + "', alg, " + 
            SHREQService.KeyDeclaration.PRIVATE_KEYS + ", unconditionally);\n" +
            "    showPriv(true);\n" +
            "    fill('" + PRM_CERT_PATH + "', alg, " + 
            SHREQService.KeyDeclaration.CERTIFICATES + ", unconditionally);\n" +
            "    showCert(document.getElementById('" + FLG_CERT_PATH + "').checked);\n" +
            "  }\n" +
            "}\n" +
            "function jwkFlagChange(flag) {\n" +
            "  if (flag) {\n" +
            "    document.getElementById('" + FLG_CERT_PATH + "').checked = false;\n" +
            "    showCert(false);\n" +
            "  }\n" +
            "}\n" +
            "function certFlagChange(flag) {\n" +
            "  showCert(flag);\n" +
            "  if (flag) {\n" +
            "    document.getElementById('" + FLG_JWK_INLINE + "').checked = false;\n" +
            "  }\n" +
            "}\n" +
            "function restoreSecurityDefaults() {\n" +
            "  let s = document.getElementById('" + PRM_ALGORITHM + "');\n" +
            "  for (let i = 0; i < s.options.length; i++) {\n" +
            "    if (s.options[i].text == '" + DEFAULT_ALGORITHM + "') {\n" +
            "      s.options[i].selected = true;\n" +
            "      break;\n" +
            "    }\n" +
            "  }\n" +
            "  setParameters('" + DEFAULT_ALGORITHM + "', true);\n" +
            "  document.getElementById('" + FLG_CERT_PATH + "').checked = false;\n" +
            "  document.getElementById('" + FLG_JWK_INLINE + "').checked = false;\n" +
            "  document.getElementById('" + FLG_IAT_PRESENT + "').checked = true;\n" +
            "  setUserData(true);\n" +
            "}\n" +
            "function algChange(alg) {\n" +
            "  setParameters(alg, true);\n" +
            "}\n" +
            "function showCert(show) {\n" +
            "  document.getElementById('" + PRM_CERT_PATH + "').style.display= show ? 'block' : 'none';\n" +
            "}\n" +
            "function showPriv(show) {\n" +
            "  document.getElementById('" + PRM_PRIVATE_KEY + "').style.display= show ? 'block' : 'none';\n" +
            "}\n" +
            "function showSec(show) {\n" +
            "  document.getElementById('" + PRM_SECRET_KEY + "').style.display= show ? 'block' : 'none';\n" +
            "}\n" +
            "function setMethod(method) {\n" +
            "  let s = document.getElementById('" + PRM_METHOD + "');\n" +
            "  for (let i = 0; i < s.options.length; i++) {\n" +
            "    if (s.options[i].text == method) {\n" +
            "      s.options[i].selected = true;\n" +
            "      break;\n" +
            "    }\n" +
            "  }\n" +
            "}\n" +
            "function restoreRequestDefaults() {\n" +
            "  let radioButtons = document.getElementsByName('" + PRM_SCHEME + "');\n" +
            "  radioButtons[0].checked = true;\n" +
            "  requestChange(true);\n" +
            "}\n" +
            "function requestChange(jsonRequest) {\n" +
            "  document.getElementById('" + PRM_JSON_DATA + "').style.display= jsonRequest ? 'block' : 'none';\n" +
            "  setMethod(jsonRequest ? '" + DEFAULT_JSON_METHOD + "' : '" + DEFAULT_URI_METHOD + "');\n" +
            "}\n" +
            "window.addEventListener('load', function(event) {\n" +
            "  setParameters(document.getElementById('" + PRM_ALGORITHM + "').value, false);\n" +
            "  setUserData(false);\n" +
            "});\n");
        HTML.standardPage(response, 
                         js.toString(),
                         html);
    }
    
    static String getParameter(HttpServletRequest request, String parameter) throws IOException {
        String string = request.getParameter(parameter);
        if (string == null) {
            throw new IOException("Missing data for: "+ parameter);
        }
        return string.trim();
    }
    
    static byte[] getBinaryParameter(HttpServletRequest request, String parameter) throws IOException {
        return getParameter(request, parameter).getBytes("utf-8");
    }

    static String getTextArea(HttpServletRequest request, String name)
            throws IOException {
        String string = getParameter(request, name);
        StringBuilder s = new StringBuilder();
        for (char c : string.toCharArray()) {
            if (c != '\r') {
                s.append(c);
            }
        }
        return s.toString();
    }

   
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
         try {
            request.setCharacterEncoding("utf-8");
            String targetUri = getTextArea(request, PRM_URI);
            String jsonData = getTextArea(request, PRM_JSON_DATA);
            String method = getParameter(request, PRM_METHOD);
            boolean jsonRequest = new Boolean(getParameter(request, PRM_SCHEME));
            JSONObjectReader additionalHeaderData = JSONParser.parse(getParameter(request, PRM_JWS_EXTRA));
            boolean keyInlining = request.getParameter(FLG_JWK_INLINE) != null;
            boolean certOption = request.getParameter(FLG_CERT_PATH) != null;
            boolean iatOption = request.getParameter(FLG_IAT_PRESENT) != null;
            SignatureAlgorithms algorithm = 
                    JOSESupport.getSignatureAlgorithm(getParameter(request, PRM_ALGORITHM));

            // Create the minimal JWS header
            JSONObjectWriter JWS_Protected_Header =
                    JOSESupport.setSignatureAlgorithm(new JSONObjectWriter(), algorithm);

            // Add any optional (by the user specified) arguments
            for (String key : additionalHeaderData.getProperties()) {
                JWS_Protected_Header.copyElement(key, key, additionalHeaderData);
            }
            
            // Get the signature key
            JOSESupport.CoreKeyHolder keyHolder;
            String validationKey;
            
            // Symmetric or asymmetric?
            if (algorithm.isSymmetric()) {
                validationKey = getParameter(request, PRM_SECRET_KEY);
                keyHolder = new JOSESymKeyHolder(DebugFormatter.getByteArrayFromHex(validationKey));
            } else {
                // To simplify UI we require PKCS #8 with the public key embedded
                // but we also support JWK which also has the public key
                byte[] privateKeyBlob = getBinaryParameter(request, PRM_PRIVATE_KEY);
                KeyPair keyPair;
                if (privateKeyBlob[0] == '{') {
                    keyPair = JSONParser.parse(privateKeyBlob).getKeyPair();
                 } else {
                    keyPair = PEMDecoder.getKeyPair(privateKeyBlob);
                }
                privateKeyBlob = null;  // Nullify it after use
                validationKey = "-----BEGIN PUBLIC KEY-----\n" +
                                new Base64().getBase64StringFromBinary(keyPair.getPublic().getEncoded()) +
                                "\n-----END PUBLIC KEY-----";

                // Add other JWS header data that the demo program fixes 
                if (certOption) {
                    JOSESupport.setCertificatePath(JWS_Protected_Header,
                            PEMDecoder.getCertificatePath(getBinaryParameter(request,
                                                                             PRM_CERT_PATH)));
                } else if (keyInlining) {
                    JOSESupport.setPublicKey(JWS_Protected_Header, keyPair.getPublic());
                }
                keyHolder = new JOSEAsymKeyHolder(keyPair.getPrivate());
            }
            String signedJSONRequest;
            if (jsonRequest) {
                // Creating JWS data to be signed
                JSONObjectReader reader = JSONParser.parse(jsonData);
                if (reader.getJSONArrayReader() != null) {
                    throw new IOException("The demo does not support signed arrays");
                }
                JSONObjectWriter writer = new JSONObjectWriter(reader);
                JSONObjectWriter shreqObject = 
                        SHREQSupport.createJSONRequestHeader(targetUri,
                                                             method,
                                                             iatOption ? new GregorianCalendar() : null);
                writer.setObject(SHREQSupport.SHREQ_LABEL, shreqObject);
                byte[] JWS_Payload = writer.serializeToBytes(JSONOutputFormats.CANONICALIZED);
        
                // Sign it using the provided algorithm and key
                String jwsString = JOSESupport.createJwsSignature(JWS_Protected_Header, 
                                                                  JWS_Payload,
                                                                  keyHolder,
                                                                  true);
                keyHolder = null;  // Nullify it after use
        
                // Create the completed object which now is in "writer"
                shreqObject.setString(SHREQSupport.JWS, jwsString);
                
                signedJSONRequest = writer.serializeToString(JSONOutputFormats.NORMALIZED);
                
                // The following is just for the demo.  That is, we want to preserve
                // the original ("untouched") JSON data for educational purposes.
                int i = signedJSONRequest.lastIndexOf("\"" + SHREQSupport.SHREQ_LABEL);
                if (signedJSONRequest.charAt(i - 1) == ',') {
                    i--;
                }
                int j = jsonData.lastIndexOf("}");
                signedJSONRequest = jsonData.substring(0, j) + 
                        signedJSONRequest.substring(i, signedJSONRequest.length() - 1) +
                        jsonData.substring(j);
            } else {
                signedJSONRequest="";
                JSONObjectWriter writer = 
                        SHREQSupport.createURIRequestPayload(targetUri,
                                                             method,
                                                             iatOption ? new GregorianCalendar() : null,
                                                             algorithm);
                byte[] JWS_Payload = writer.serializeToBytes(JSONOutputFormats.NORMALIZED);
                String jwsString = JOSESupport.createJwsSignature(JWS_Protected_Header, 
                                                                  JWS_Payload,
                                                                  keyHolder,
                                                                  false);
                targetUri += (targetUri.contains("?") ?
                        '&' : '?') + SHREQSupport.SHREQ_LABEL + "=" + jwsString;
            }

            // We terminate by validating the signature as well
            request.getRequestDispatcher("validate?" +
                ValidateServlet.JSON_PAYLOAD + 
                "=" +
                URLEncoder.encode(signedJSONRequest, "utf-8") +
                "&" +
                ValidateServlet.TARGET_URI + 
                "=" +
                URLEncoder.encode(targetUri, "utf-8") +
                "&" +
                ValidateServlet.JWS_VALIDATION_KEY + 
                "=" +
                URLEncoder.encode(validationKey, "utf-8") +
                "&" +
                ValidateServlet.HTTP_METHOD + 
                "=" +
                URLEncoder.encode(method, "utf-8"))
                    .forward(request, response);
        } catch (Exception e) {
            HTML.errorPage(response, e);
        }
    }
}
