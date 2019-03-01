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
import java.util.GregorianCalendar;
import java.util.Vector;
import java.util.logging.Logger;

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
import org.webpki.shreq.SHREQSupport;
import org.webpki.util.Base64URL;
import org.webpki.util.DebugFormatter;
import org.webpki.util.PEMDecoder;

public class ValidateServlet extends BaseGuiServlet {

    private static final long serialVersionUID = 1L;

    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        try {
            request.setCharacterEncoding("utf-8");
            if (!request.getContentType().startsWith("application/x-www-form-urlencoded")) {
                throw new IOException("Unexpected MIME type:" + request.getContentType());
            }
            logger.info("JSON Signature Verification Entered");
            // Get the two input data items
            String signedJsonObject = getParameter(request, JSON_PAYLOAD);
            boolean jsonRequest = signedJsonObject.length() > 0;
            String uri = getParameter(request, TARGET_URI);
            String validationKey = getParameter(request, JWS_VALIDATION_KEY);
            String requestMethod = getParameter(request, HTTP_METHOD);

            // Parse the JSON data
            StringBuilder html = new StringBuilder();
            if (jsonRequest) {
                JSONObjectReader parsedObject = JSONParser.parse(signedJsonObject);
/*
            
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
            
            // Now begin the real work...

            // Decode SHREQ object.  It also removes the "jwe" property
            SHREQSupport.ReceivedJSONRequestHeader shreqHeader =
                    SHREQSupport.getJSONRequestHeader(parsedObject);
            
            // Get the actual JSON data bytes and remove the signature
            byte[] JWS_Payload = parsedObject.serializeToBytes(JSONOutputFormats.CANONICALIZED);

    

            // Start decoding the JWS header.  Algorithm is the minimum
            SignatureAlgorithms algorithm = 
                    JOSESupport.getSignatureAlgorithm(JWS_Protected_Header);

            // We don't bother about any other header data than possible public key
            // elements modulo JKU and X5U
            PublicKey jwsSuppliedPublicKey = null;
            X509Certificate[] certificatePath = null;
            if (JWS_Protected_Header.hasProperty(JOSESupport.JWK_JSON)) {
                jwsSuppliedPublicKey = JOSESupport.getPublicKey(JWS_Protected_Header);
            }
            StringBuilder certificateData = null;
            if (JWS_Protected_Header.hasProperty(JOSESupport.X5C_JSON)) {
                if (jwsSuppliedPublicKey != null) {
                    throw new GeneralSecurityException("Both X5C and JWK?");
                }
                certificatePath = JOSESupport.getCertificatePath(JWS_Protected_Header);
                jwsSuppliedPublicKey = certificatePath[0].getPublicKey();
                for (X509Certificate certificate : certificatePath) {
                    if (certificateData == null) {
                        certificateData = new StringBuilder();
                    } else {
                        certificateData.append("<br>&nbsp;<br>");
                    }
                    certificateData.append(
                        HTML.encode(new CertificateInfo(certificate).toString())
                            .replace("\n", "<br>").replace("  ", ""));
                }
            }
            
            // Recreate the validation key and validate the signature
            JOSESupport.CoreSignatureValidator validator;
            boolean jwkValidationKey = validationKey.startsWith("{");
            if (algorithm.isSymmetric()) {
                if (jwsSuppliedPublicKey != null) {
                    throw new GeneralSecurityException("Public key header elements in a HMAC signature?");
                }
                validator = 
                        new JOSEHmacValidator(DebugFormatter.getByteArrayFromHex(validationKey),
                                                  (MACAlgorithms) algorithm);
            } else {
                AsymSignatureAlgorithms asymSigAlg = (AsymSignatureAlgorithms) algorithm;
                PublicKey externalPublicKey = jwkValidationKey ? 
                    JSONParser.parse(validationKey).getCorePublicKey(AlgorithmPreferences.JOSE)
                                                                :
                    PEMDecoder.getPublicKey(validationKey.getBytes("utf-8"));

                if (jwsSuppliedPublicKey != null && !jwsSuppliedPublicKey.equals(externalPublicKey)) {
                    throw new GeneralSecurityException("Supplied public key differs from the one derived from the JWS header");
                }
                validator = new JOSEAsymSignatureValidator(externalPublicKey, asymSigAlg);
            }
            JOSESupport.validateJwsSignature(jwsHeaderB64, JWS_Payload, JWS_Signature, validator);
            StringBuilder html = new StringBuilder(
                    "<div class=\"header\"> Signature Successfully Validated</div>")
                .append(HTML.fancyBox("signed", prettySignature, "JSON object signed by an embedded JWS element"))           
                .append(HTML.fancyBox("header", 
                                      JWS_Protected_Header.serializeToString(JSONOutputFormats.PRETTY_HTML),
                                      "Decoded JWS header"))
                .append(HTML.fancyBox("vkey",
                                      jwkValidationKey ? 
                                          JSONParser.parse(validationKey)
                                              .serializeToString(JSONOutputFormats.PRETTY_HTML)
                                                       :
                                      HTML.encode(validationKey).replace("\n", "<br>"),
                                      "Signature validation " + (algorithm.isSymmetric() ? 
                                             "secret key in hexadecimal" :
                                             "public key in " + 
                                             (jwkValidationKey ? "JWK" : "PEM") +
                                             " format")))
                .append(HTML.fancyBox("canonical", 
                                      HTML.encode(new String(JWS_Payload, "utf-8")),
                                      "Canonical version of the JSON data (with possible line breaks " +
                                      "for display purposes only)"));
            if (certificateData != null) {
                html.append(HTML.fancyBox("certpath", 
                                          certificateData.toString(),
                                          "Core certificate data"));
            }
*/
                html.append(parsedObject.serializeToString(JSONOutputFormats.PRETTY_HTML));
            } else {
                html.append("hi");
            }
            html.append(uri);
            // Finally, print it out
            HTML.standardPage(response, null, html.append("<div style=\"padding:10pt\"></div>"));
        } catch (Exception e) {
            HTML.errorPage(response, e);
        }
    }

    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {

        if (sampleRequest == null) {
            synchronized(this) {
                JSONObjectWriter JWS_Protected_Header =
                        JOSESupport.setSignatureAlgorithm(new JSONObjectWriter(), 
                                                          AsymSignatureAlgorithms.ECDSA_SHA256);
                JSONObjectWriter writer = 
                        new JSONObjectWriter(JSONParser.parse(TEST_MESSAGE));
                
                JSONObjectWriter shreqObject = 
                        SHREQSupport.createJSONRequestHeader(getDefaultUri(request),
                                                             "POST",
                                                             new GregorianCalendar());
                writer.setObject(SHREQSupport.SHREQ_LABEL, shreqObject);
                byte[] JWS_Payload = writer.serializeToBytes(JSONOutputFormats.CANONICALIZED);

                // Sign it using the provided algorithm and key
                PrivateKey privateKey = 
                        SHREQService.predefinedKeyPairs
                            .get(AsymSignatureAlgorithms.ECDSA_SHA256
                                    .getAlgorithmId(AlgorithmPreferences.JOSE)).getPrivate();
                try {
                    String jwsString = 
                            JOSESupport.createJwsSignature(JWS_Protected_Header, 
                                                           JWS_Payload,
                                                           new JOSEAsymKeyHolder(privateKey),
                                                           true);
                    // Create the completed object which now is in "writer"
                    shreqObject.setString(SHREQSupport.JWS, jwsString);
                    
                    sampleRequest = writer.serializeToString(JSONOutputFormats.PRETTY_PRINT);

                } catch (GeneralSecurityException e) {
                    sampleRequest = "Internal error - Call admin";
                }
            }
        }
        HTML.standardPage(response, null, new StringBuilder(
                "<form name=\"shoot\" method=\"POST\" action=\"validate\">" +
                "<div class=\"header\">SHREQ Message Validation</div>")
            .append(HTML.fancyText(true,
                TARGET_URI,
                1, 
                HTML.encode(getDefaultUri(request)),
                "Target URI"))
            .append(HTML.fancyText(true,
                HTTP_METHOD,
                1, 
                HTML.encode("POST"),
                "Anticipated method"))
            .append(HTML.fancyText(true,
                JSON_PAYLOAD,
                10, 
                HTML.encode(sampleRequest),
                "Paste a signed JSON request in the text box or try with the default"))
            .append(HTML.fancyText(true,
                JWS_VALIDATION_KEY,
                4, 
                HTML.encode(SHREQService.sampleKey),
"Validation key (secret key in hexadecimal or public key in PEM or &quot;plain&quot; JWK format)"))

            .append(
                "<div style=\"display:flex;justify-content:center\">" +
                "<div class=\"stdbtn\" onclick=\"document.forms.shoot.submit()\">" +
                "Validate JSON Signature" +
                "</div>" +
                "</div>" +
                "</form>" +
                "<div>&nbsp;</div>"));
    }
}