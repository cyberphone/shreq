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

import java.security.cert.X509Certificate;

import java.text.SimpleDateFormat;
import java.util.GregorianCalendar;
import java.util.LinkedHashMap;
import java.util.TimeZone;
import java.util.Vector;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.CertificateInfo;
import org.webpki.crypto.MACAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;

import org.webpki.jose.JOSEAsymKeyHolder;
import org.webpki.jose.JOSEAsymSignatureValidator;
import org.webpki.jose.JOSEHmacValidator;
import org.webpki.jose.JOSESupport;

import org.webpki.shreq.JSONRequestValidation;
import org.webpki.shreq.SHREQSupport;
import org.webpki.shreq.URIRequestValidation;
import org.webpki.shreq.ValidationCore;
import org.webpki.shreq.ValidationKeyService;

import org.webpki.util.DebugFormatter;
import org.webpki.util.PEMDecoder;

public class ValidateServlet extends BaseGuiServlet implements ValidationKeyService {

    private static final long serialVersionUID = 1L;

    static String sampleJsonRequest_JS;
    static String sampleUriRequestUri;
    
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        try {
            request.setCharacterEncoding("utf-8");
            if (!request.getContentType().startsWith("application/x-www-form-urlencoded")) {
                throw new IOException("Unexpected MIME type:" + request.getContentType());
            }
            // Get the two input data items
            String targetUri = getParameter(request, TARGET_URI);
            String signedJsonObject = getParameter(request, JSON_PAYLOAD);
            boolean jsonRequest = new Boolean(getParameter(request, REQUEST_TYPE));
            LinkedHashMap<String,String> httpHeaderData = createHeaderData(getParameter(request, TXT_OPT_HEADERS));
            String validationKey = getParameter(request, JWS_VALIDATION_KEY);
            String targetMethod = getParameter(request, PRM_HTTP_METHOD);
            ValidationCore validationCore = null;

            // Determining Request Type
            if (jsonRequest) {
                JSONObjectReader parsedObject = JSONParser.parse(signedJsonObject);
                // Create a pretty-printed JSON object without canonicalization
                String prettySignature = 
                        parsedObject.serializeToString(JSONOutputFormats.PRETTY_HTML);
                Vector<String> tokens = 
                        new JSONTokenExtractor().getTokens(signedJsonObject);
                int fromIndex = 0;
                for (String token : tokens) {
                    int start = prettySignature.indexOf("<span ", fromIndex);
                    int stop = prettySignature.indexOf("</span>", start);
                    // <span style="color:#C00000">
                    prettySignature = 
                            prettySignature.substring(0, 
                                                      start + 28) + 
                                                         token + 
                                                         prettySignature.substring(stop);
                    fromIndex = start + 1;
                }
                signedJsonObject = prettySignature;
                validationCore = new JSONRequestValidation(targetUri,
                                                           targetMethod,
                                                           httpHeaderData,
                                                           parsedObject);
            } else {
                validationCore = new URIRequestValidation(targetUri,
                                                          targetMethod, 
                                                          httpHeaderData);
            }

            // Now assign the key
            boolean jwkValidationKey = validationKey.startsWith("{");
            validationCore.setCookie(jwkValidationKey ?
                    JSONParser.parse(validationKey).getCorePublicKey(AlgorithmPreferences.JOSE)
                                                                :
                    validationKey.contains("-----") ?
                 PEMDecoder.getPublicKey(validationKey.getBytes("utf-8")) :
                 DebugFormatter.getByteArrayFromHex(validationKey));
            
            
            // Core Request Data Successfully Collected - Validate!
            validationCore.validate(this);

            // Parse the JSON data
            
            StringBuilder html = new StringBuilder(
                    "<div class=\"header\">Request Successfully Validated</div>")
                .append(HTML.fancyBox("targeturi", targetUri, 
                    "Target URI to be accessed by an HTTP " + targetMethod + " request"));  
            if (jsonRequest) {
                html.append(HTML.fancyBox("httpjsonbody", signedJsonObject, 
                                      "HTTP Body - JSON object signed by an embedded JWS element"));
            }
            html.append(HTML.fancyBox("jwsheader", 
                                      validationCore.getJwsProtectedHeader()
                                          .serializeToString(JSONOutputFormats.PRETTY_HTML),
                                      "Decoded JWS header"))
                .append(HTML.fancyBox("vkey",
                                      jwkValidationKey ? 
                                          JSONParser.parse(validationKey)
                                              .serializeToString(JSONOutputFormats.PRETTY_HTML)
                                                       :
                                      HTML.encode(validationKey).replace("\n", "<br>"),
                                      "Signature validation " +
                                      (validationCore.getSignatureAlgorithm().isSymmetric() ? 
                                             "secret key in hexadecimal" :
                                             "public key in " + 
                                             (jwkValidationKey ? "JWK" : "PEM") +
                                             " format")));
            if (jsonRequest) {
                html.append(HTML.fancyBox(
                        "canonical", 
                        HTML.encode(new String(validationCore.getJwsPayload(), "utf-8")),
                        "Canonical version of the JSON data (what is actually signed) with possible line breaks " +
                        "for display purposes only"));
            } else {
                html.append(HTML.fancyBox(
                        "jwspayload", 
                        JSONParser.parse(validationCore.getJwsPayload()).serializeToString(JSONOutputFormats.PRETTY_HTML),
                        "Decoded JWS Payload"));
            }
            if (validationCore.getCertificatePath() != null) {
                StringBuilder certificateData = null;
                for (X509Certificate certificate : validationCore.getCertificatePath()) {
                    if (certificateData == null) {
                        certificateData = new StringBuilder();
                    } else {
                        certificateData.append("<br>&nbsp;<br>");
                    }
                    certificateData.append(
                        HTML.encode(new CertificateInfo(certificate).toString())
                            .replace("\n", "<br>").replace("  ", ""));
                }
                html.append(HTML.fancyBox("certpath", 
                                          certificateData.toString(),
                                          "Core certificate data"));
            }
            String time;
            if (validationCore.getIssuedAt() == null) {
                time = "Request does not contain a time stamp";
            } else {
                SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd' 'HH:mm:ss 'UTC'");
                sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
                time = sdf.format(validationCore.getIssuedAt().getTime());
            }
            html.append(HTML.fancyBox(
                    "timestamp", 
                    time,
                    "Time stamp"));
            HTML.standardPage(response, null, html.append("<div style=\"padding:10pt\"></div>"));
        } catch (Exception e) {
            HTML.errorPage(response, e);
        }
    }

    @Override
    public JOSESupport.CoreSignatureValidator getSignatureValidator(ValidationCore validationCore,
                                                                    SignatureAlgorithms signatureAlgorithm,
                                                                    PublicKey publicKey, 
                                                                    String keyId)
    throws IOException, GeneralSecurityException {
        if (signatureAlgorithm.isSymmetric()) {
            return new JOSEHmacValidator((byte[])validationCore.getCookie(),
                                         (MACAlgorithms) signatureAlgorithm);
        }
        PublicKey validationKey = (PublicKey)validationCore.getCookie();
        if (publicKey != null && !publicKey.equals(validationKey)) {
            throw new GeneralSecurityException("In-lined public key differs from predefined public key");
        }
        return new JOSEAsymSignatureValidator(validationKey, 
                                             (AsymSignatureAlgorithms)signatureAlgorithm);
    }


    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        String targetUri = getDefaultUri(request);
        if (sampleJsonRequest_JS == null) {
            synchronized(this) {
                try {
                    LinkedHashMap<String,String> noHeaders = new LinkedHashMap<String,String>();
                    AsymSignatureAlgorithms signatureAlgorithm = AsymSignatureAlgorithms.ECDSA_SHA256;
                    JSONObjectWriter JWS_Protected_Header =
                            JOSESupport.setSignatureAlgorithm(new JSONObjectWriter(), 
                                                              signatureAlgorithm);
                    JSONObjectWriter writer = 
                            new JSONObjectWriter(JSONParser.parse(TEST_MESSAGE));
                    
                    JSONObjectWriter shreqObject = 
                            SHREQSupport.createJSONRequestHeader(targetUri,
                                                                 SHREQSupport.SHREQ_DEFAULT_JSON_METHOD,
                                                                 new GregorianCalendar(),
                                                                 noHeaders,
                                                                 signatureAlgorithm);
                    writer.setObject(SHREQSupport.SHREQ_LABEL, shreqObject);
                    byte[] JWS_Payload = writer.serializeToBytes(JSONOutputFormats.CANONICALIZED);
        
                    // Sign it using the provided algorithm and key
                    PrivateKey privateKey = 
                            SHREQService.predefinedKeyPairs
                                .get(signatureAlgorithm
                                        .getAlgorithmId(AlgorithmPreferences.JOSE)).getPrivate();
                    String jwsString = 
                            JOSESupport.createJwsSignature(JWS_Protected_Header, 
                                                           JWS_Payload,
                                                           new JOSEAsymKeyHolder(privateKey),
                                                           true);
                    // Create the completed object which now is in "writer"
                    shreqObject.setString(SHREQSupport.SHREQ_JWS_STRING, jwsString);
                    
                    sampleJsonRequest_JS =
                            HTML.javaScript(writer.serializeToString(JSONOutputFormats.PRETTY_PRINT));

                    shreqObject = 
                            SHREQSupport.createURIRequestPayload(targetUri,
                                                                 SHREQSupport.SHREQ_DEFAULT_URI_METHOD,
                                                                 new GregorianCalendar(),
                                                                 noHeaders,
                                                                 signatureAlgorithm);
                    sampleUriRequestUri = SHREQSupport.addJwsToTargetUri(
                            targetUri,
                            JOSESupport.createJwsSignature(
                                    JWS_Protected_Header, 
                                    shreqObject.serializeToBytes(JSONOutputFormats.NORMALIZED),
                                    new JOSEAsymKeyHolder(privateKey),
                                    false));

                } catch (GeneralSecurityException e) {
                    sampleJsonRequest_JS = "Internal error - Call admin";
                }
            }
        }
        StringBuilder html = new StringBuilder(
            "<form name=\"shoot\" method=\"POST\" action=\"validate\">" +
            "<div class=\"header\">SHREQ Message Validation</div>")

        .append(
            HTML.fancyText(
                true,
                TARGET_URI,
                1, 
                HTML.encode(targetUri),
                "Target URI"))

        .append(
            HTML.fancyText(
                true,
                JSON_PAYLOAD,
                10, 
                "",
                "Paste a signed JSON request in the text box or try with the default"))

        .append(
            HTML.fancyText(
                false,
                TXT_OPT_HEADERS,
                4,
                "",
                "Optional HTTP headers, each on a separate line"))

        .append(getRequestParameters())

        .append(
            HTML.fancyText(
                true,
                JWS_VALIDATION_KEY,
                4, 
                HTML.encode(SHREQService.sampleKey),
"Validation key (secret key in hexadecimal or public key in PEM or &quot;plain&quot; JWK format)"))

        .append(
            "<div style=\"display:flex;justify-content:center\">" +
            "<div class=\"stdbtn\" onclick=\"document.forms.shoot.submit()\">" +
            "Validate Signed Request" +
            "</div>" +
            "</div>" +
            "</form>" +
            "<div>&nbsp;</div>");

        StringBuilder js = new StringBuilder("\"use strict\";\n")
        .append(

            "function setUserData(unconditionally) {\n" +
            "  let element = document.getElementById('" + JSON_PAYLOAD + "').children[1];\n" +
            "  if (unconditionally || element.value == '') element.value = '")
        .append(sampleJsonRequest_JS)
        .append("';\n" +
            "  element = document.getElementById('" + TARGET_URI + "').children[1];\n" +
            "  if (unconditionally || element.value == '') element.value = '")
        .append(targetUri)
        .append("';\n" +
            "}\n" +
            "function showJson(show) {\n" +
            "  document.getElementById('" + JSON_PAYLOAD + "').style.display= show ? 'block' : 'none';\n" +
            "}\n" +
            "function setMethod(method) {\n" +
            "  let s = document.getElementById('" + PRM_HTTP_METHOD + "');\n" +
            "  for (let i = 0; i < s.options.length; i++) {\n" +
            "    if (s.options[i].text == method) {\n" +
            "      s.options[i].selected = true;\n" +
            "      break;\n" +
            "    }\n" +
            "  }\n" +
            "}\n" +
            "function showHeaders(show) {\n" +
            "  document.getElementById('" + TXT_OPT_HEADERS + "').style.display= show ? 'block' : 'none';\n" +
            "}\n" +
            "function restoreRequestDefaults() {\n" +
            "  let radioButtons = document.getElementsByName('" + REQUEST_TYPE + "');\n" +
            "  radioButtons[0].checked = true;\n" +
            "  requestChange(true);\n" +
            "  document.getElementById('" + FLG_HEADERS + "').checked = false;\n" +
            "  showHeaders(false);\n" +
            "  setUserData(true);\n" +
            "}\n" +
            "function requestChange(jsonRequest) {\n" +
            "  document.getElementById('" + JSON_PAYLOAD + "').style.display= jsonRequest ? 'block' : 'none';\n" +
            "  setMethod(jsonRequest ? '" + DEFAULT_JSON_METHOD + "' : '" + DEFAULT_URI_METHOD + "');\n" +
            "  let element = document.getElementById('" + TARGET_URI + "').children[1];\n" +
            "  if (jsonRequest) {\n" +
            "    if (element.value == '" + sampleUriRequestUri + "') {\n" +
            "      element.value = '" + targetUri + "';\n" +
            "    }\n" +
            "  } else {\n" +
            "    if (element.value == '" + targetUri + "') {\n" +
            "      element.value = '" + sampleUriRequestUri + "';\n" +
            "    }\n" +
            "  }\n" +
            "}\n" +
            "function headerFlagChange(flag) {\n" +
            "  showHeaders(flag);\n" +
            "}\n" +
            "window.addEventListener('load', function(event) {\n" +
            "  let radioButtons = document.getElementsByName('" + REQUEST_TYPE + "');\n" +
            "  showJson(radioButtons[0].checked);\n" +
            "  showHeaders(document.getElementById('" + FLG_HEADERS + "').checked);\n" +
            "  setUserData(false);\n" +
            "});\n");
        HTML.standardPage(response, js.toString(), html);
    }
}
