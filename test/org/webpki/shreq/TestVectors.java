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
package org.webpki.shreq;

import java.io.File;
import java.io.IOException;

import java.security.KeyPair;

import java.util.GregorianCalendar;
import java.util.LinkedHashMap;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.MACAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;

import org.webpki.jose.JOSEAsymKeyHolder;
import org.webpki.jose.JOSESupport;
import org.webpki.jose.JOSESymKeyHolder;

import org.webpki.shreq.SHREQSupport;

import org.webpki.util.Base64;
import org.webpki.util.DebugFormatter;
import org.webpki.util.ISODateTime;
import org.webpki.util.PEMDecoder;
import org.webpki.util.ArrayUtil;

public class TestVectors {
    
    static String keyDirectory;
    
    static int testVectorNumber;
    
    static StringBuilder rfcText = new StringBuilder();
    
    static final int RFC_ARTWORK_LINE_MAX = 64;
    
    static class Test {
        String uri;
        String method;
        String optionalJSONBody;
        SignatureAlgorithms signatureAlgorithm;
        String optionalOverrideHashAlgorithm;
        String keyAlgName;
        GregorianCalendar optionalTimeStamp;
        LinkedHashMap<String,String> optionalHeaders;
        
        JOSESupport.CoreKeyHolder keyHolder;
        String keyInRFCText;
        String keyRFCDescription;
        String signatureAlgorithmId;
        JSONObjectWriter secinf;
        byte[] JWS_Payload;
        JSONObjectWriter JWS_Protected_Header;
		String signedUri;

        Test(String uri,
             String method,
             String optionalJSONBody,
             SignatureAlgorithms signatureAlgorithm,
             String optionalOverrideHashAlgorithm,
             String keyAlgName,
             GregorianCalendar optionalTimeStamp,
             LinkedHashMap<String,String> optionalHeaders) throws Exception {
            this.uri = uri;
            this.method = method;
            this.optionalJSONBody = optionalJSONBody;
            this.signatureAlgorithm = signatureAlgorithm;
            this.optionalOverrideHashAlgorithm = optionalOverrideHashAlgorithm;
            this.keyAlgName = keyAlgName;
            this.optionalTimeStamp = optionalTimeStamp;
            this.optionalHeaders  = optionalHeaders == null ? 
                         new LinkedHashMap<String,String>() : optionalHeaders;
            createVector();
        }
        
        String utf8(byte[] data) throws IOException {
            return new String(data, "utf-8");
        }
        
        void createVector() throws Exception {
            signatureAlgorithmId = signatureAlgorithm.getAlgorithmId(AlgorithmPreferences.JOSE);
            SHREQSupport.overridedHashAlgorithm = optionalOverrideHashAlgorithm;
            if (signatureAlgorithm.isSymmetric()) {
                String keyInHex = utf8(readKey(keyAlgName + "bitkey.hex"));
                keyInRFCText = keyInHex;
                keyRFCDescription = "Symmetric signature validation key, here in hexadecimal notation:";
                keyHolder = new JOSESymKeyHolder(DebugFormatter.getByteArrayFromHex(keyInHex));
            } else {
                KeyPair keyPair = PEMDecoder.getKeyPair(readKey(keyAlgName + "privatekey.pem"));
                keyRFCDescription = "Public signature validation key, here in PEM format:";
                keyInRFCText = 
                    "-----BEGIN PUBLIC KEY-----\n" +
                    new Base64(RFC_ARTWORK_LINE_MAX).getBase64StringFromBinary(keyPair.getPublic().getEncoded()) +
                    "\n-----END PUBLIC KEY-----";
                keyHolder = new JOSEAsymKeyHolder(keyPair.getPrivate());
            }

            JWS_Protected_Header = JOSESupport.setSignatureAlgorithm(new JSONObjectWriter(), 
                                                                     signatureAlgorithm);
            secinf = new JSONObjectWriter();
            if (optionalJSONBody == null) {
                uriRequest();
            } else {
                jsonRequest(JSONParser.parse(optionalJSONBody));
            }
            rfcText.append("<section anchor=\"testvector.")
                   .append(++testVectorNumber)
                   .append("\" title=\"Type=")
                   .append(optionalJSONBody == null ? "URI" : "JSON")
                   .append(", Method=")
                   .append(method)
                   .append(", Algorithm=")
                   .append(signatureAlgorithmId)
                   .append("\">\n<t>\nTarget URI:\n</t>\n")
                   .append(artWork(lineCutter(uri)));
            
            if (optionalJSONBody == null) {
                rfcText.append("<t>\nSigned URI:\n</t>\n")
                       .append(artWork(lineCutter(signedUri)))
                       .append("<t>\nDecoded JWS Payload:\n</t>\n")
                       .append(artWork(lineCutter(secinf.serializeToString(JSONOutputFormats.PRETTY_PRINT))));
            } else {
                rfcText.append("<t>\nJSON Body:\n</t>\n")
                       .append(artWork(lineCutter(optionalJSONBody)));
            }
            if (optionalOverrideHashAlgorithm != null) {
                rfcText.append("<t>\nNote the overridden hash algorithm.\n</t>\n");
            }
            if (!optionalHeaders.isEmpty()) {
                StringBuilder headers = new StringBuilder();
                for (String header : optionalHeaders.keySet()) {
                    headers.append(header)
                           .append(": ")
                           .append(optionalHeaders.get(header))
                           .append('\n');
                }
                rfcText.append("<t>\nRequired HTTP Headers:\n</t>\n")
                       .append(artWork(headers.toString().trim()));
            }
            rfcText.append("<t>\n")
                   .append(keyRFCDescription)
                   .append("\n</t>\n")
                   .append(artWork(keyInRFCText))
                   .append("</section>\n");
        }

        String lineCutter(String string) {
            int position = 0;
            StringBuilder cutted = new StringBuilder();
            for (char c : string.toCharArray()) {
                if (c == '\n') {
                    position = 0;
                } else if (position++ == RFC_ARTWORK_LINE_MAX) {
                    cutted.append('\n');
                    position = 1;
                }
                cutted.append(c);
            }
            return cutted.toString().trim();
        }

        StringBuilder artWork(String string) {
            StringBuilder total = new StringBuilder("<t><figure align=\"left\"><artwork><![CDATA[  ");
            for (char c : string.toCharArray()) {
                total.append(c);
                if (c == '\n') {
                    total.append("  ");
                }
            }
            return total.append("]]></artwork></figure></t>\n");
        }

        void jsonRequest(JSONObjectReader message) throws Exception {
            secinf = SHREQSupport.createJSONRequestSecInf(uri,
                                                          method,
                                                          optionalTimeStamp,
                                                          optionalHeaders,
                                                          signatureAlgorithm);
            JSONObjectWriter writer = new JSONObjectWriter(message);
            writer.setObject(SHREQSupport.SHREQ_SECINF_LABEL, secinf);
            JWS_Payload = writer.serializeToBytes(JSONOutputFormats.CANONICALIZED);
            String jwsString = JOSESupport.createJwsSignature(JWS_Protected_Header, 
                                                              JWS_Payload,
                                                              keyHolder,
                                                              true);
            // Create the completed object which now is in "writer"
            secinf.setString(SHREQSupport.SHREQ_JWS_STRING, jwsString);
            optionalJSONBody = writer.serializeToString(JSONOutputFormats.PRETTY_PRINT);
        }

        void uriRequest() throws Exception {
            secinf = SHREQSupport.createURIRequestSecInf(uri,
                                                         method,
                                                         optionalTimeStamp,
                                                         optionalHeaders,
                                                         signatureAlgorithm);
            String jwsString = JOSESupport.createJwsSignature(JWS_Protected_Header, 
                    secinf.serializeToBytes(JSONOutputFormats.NORMALIZED),
                                                         keyHolder,
                                                         false);
            signedUri = SHREQSupport.addJwsToTargetUri(uri, jwsString);
        }
    }

    public static void main(String[] argv) {
        try {
            SHREQSupport.useDefaultForMethod = true;
            keyDirectory = argv[0];
            GregorianCalendar frozen = 
                    ISODateTime.parseDateTime("2019-03-07T09:45:00Z", 
                                              ISODateTime.UTC_NO_SUBSECONDS);
            String john = "{\"name\":\"John Doe\", \"profession\":\"Unknown\"}";
            String jane = "{\"name\":\"Jane Smith\", \"profession\":\"Hacker\"}";
            LinkedHashMap<String,String> header = new LinkedHashMap<String,String>();
            header.put("x-debug", "full");
            
            /*
                String uri
                String method
                String optionalJSONBody
                SignatureAlgorithms signatureAlgorithm
                String optionalOverrideHashAlgorithm
                String keyAlgName
                GregorianCalendar optionalTimeStamp
                LinkedHashMap<String,String> optionalHeaders
             */
            new Test(
                    "https://example.com/users/456",
                    "GET",
                    null,
                    MACAlgorithms.HMAC_SHA256,
                    null,
                    "a256",
                    frozen,
                    null);

            new Test(
                    "https://example.com/users",
                    "POST",
                    john,
                    AsymSignatureAlgorithms.ECDSA_SHA256,
                    null,
                    "P256",
                    frozen,
                    null);

            new Test(
                    "https://example.com/users/456",
                    "PUT",
                    jane,
                    AsymSignatureAlgorithms.ECDSA_SHA256,
                    null,
                    "P256",
                    frozen,
                    null);

            new Test(
                    "https://example.com/users/456",
                    "DELETE",
                    null,
                    AsymSignatureAlgorithms.RSA_SHA256,
                    "S512",
                    "R2048",
                    frozen,
                    header);

            ArrayUtil.writeFile(argv[1], rfcText.toString().getBytes("utf-8"));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static byte[] readKey(String filename) throws IOException {
        return ArrayUtil.readFile(keyDirectory + File.separator + filename);
    }
}
