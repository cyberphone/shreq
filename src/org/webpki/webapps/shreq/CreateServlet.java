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

import javax.servlet.ServletException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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

public class CreateServlet extends BaseGuiServlet {
    
    private static final long serialVersionUID = 1L;

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
                        TARGET_URI,
                        1,
                        "",
                        "Target URI"))

            .append(
                HTML.fancyText(
                        true,
                        JSON_PAYLOAD,
                        10,
                        "",
                        "Paste an unsigned JSON object in the text box or try with the default"))

            .append(
                HTML.fancyText(
                        false,
                        OPT_HEADERS,
                        4,
                        "",
                        "Optional HTTP headers, each on a separate line"))

            .append(getRequestParameters())

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
                .append(checkBox(FLG_DEF_METHOD, "Include method also when default", 
                                 false, null))
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
            "  let element = document.getElementById('" + JSON_PAYLOAD + "').children[1];\n" +
            "  if (unconditionally || element.value == '') element.value = '")
          .append(HTML.javaScript(TEST_MESSAGE))
          .append("';\n" +
            "  element = document.getElementById('" + PRM_JWS_EXTRA + "').children[1];\n" +
            "  if (unconditionally || element.value == '') element.value = '{\\n}';\n" +
            "  element = document.getElementById('" + TARGET_URI + "').children[1];\n" +
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
            "function showJson(show) {\n" +
            "  document.getElementById('" + JSON_PAYLOAD + "').style.display= show ? 'block' : 'none';\n" +
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
            "  let s = document.getElementById('" + HTTP_METHOD + "');\n" +
            "  for (let i = 0; i < s.options.length; i++) {\n" +
            "    if (s.options[i].text == method) {\n" +
            "      s.options[i].selected = true;\n" +
            "      break;\n" +
            "    }\n" +
            "  }\n" +
            "}\n" +
            "function showHeaders(show) {\n" +
            "  document.getElementById('" + OPT_HEADERS + "').style.display= show ? 'block' : 'none';\n" +
            "}\n" +
            "function restoreRequestDefaults() {\n" +
            "  let radioButtons = document.getElementsByName('" + PRM_SCHEME + "');\n" +
            "  radioButtons[0].checked = true;\n" +
            "  requestChange(true);\n" +
            "  document.getElementById('" + FLG_HEADERS + "').checked = false;\n" +
            "  showHeaders(false);\n" +
            "}\n" +
            "function requestChange(jsonRequest) {\n" +
            "  document.getElementById('" + JSON_PAYLOAD + "').style.display= jsonRequest ? 'block' : 'none';\n" +
            "  setMethod(jsonRequest ? '" + DEFAULT_JSON_METHOD + "' : '" + DEFAULT_URI_METHOD + "');\n" +
            "}\n" +
            "function headerFlagChange(flag) {\n" +
            "  showHeaders(flag);\n" +
            "}\n" +
            "window.addEventListener('load', function(event) {\n" +
            "  setParameters(document.getElementById('" + PRM_ALGORITHM + "').value, false);\n" +
            "  let radioButtons = document.getElementsByName('" + PRM_SCHEME + "');\n" +
            "  showJson(radioButtons[0].checked);\n" +
            "  showHeaders(document.getElementById('" + FLG_HEADERS + "').checked);\n" +
            "  setUserData(false);\n" +
            "});\n");
        HTML.standardPage(response, 
                         js.toString(),
                         html);
    }
    
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
         try {
            request.setCharacterEncoding("utf-8");
            String targetUri = getTextArea(request, TARGET_URI);
            String jsonData = getTextArea(request, JSON_PAYLOAD);
            String method = getParameter(request, HTTP_METHOD);
            boolean jsonRequest = new Boolean(getParameter(request, PRM_SCHEME));
            JSONObjectReader additionalHeaderData = JSONParser.parse(getParameter(request, PRM_JWS_EXTRA));
            boolean keyInlining = request.getParameter(FLG_JWK_INLINE) != null;
            boolean certOption = request.getParameter(FLG_CERT_PATH) != null;
            boolean iatOption = request.getParameter(FLG_IAT_PRESENT) != null;
            boolean forceMethod = request.getParameter(FLG_DEF_METHOD) != null;
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
                        SHREQSupport.createJSONRequestHeader(
                                targetUri,
                                forceMethod ||
                                !method.equals(SHREQSupport.DEFAULT_JSON_REQUEST_METHOD) ?
                                        method : null,
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
                        SHREQSupport.createURIRequestPayload(
                                targetUri,
                                forceMethod ||
                                !method.equals(SHREQSupport.DEFAULT_URI_REQUEST_METHOD) ?
                                        method : null,
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
