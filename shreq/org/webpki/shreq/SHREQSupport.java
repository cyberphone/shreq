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

import java.io.IOException;

import java.security.GeneralSecurityException;

import java.util.GregorianCalendar;
import java.util.LinkedHashMap;

import java.util.regex.Pattern;

import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;

import org.webpki.json.JSONObjectWriter;

public class SHREQSupport {
    
    private SHREQSupport() {}
    
    public static final String SHREQ_SECINF_LABEL        = ".secinf"; // For JSON based requests only
    
    public static final String SHREQ_TARGET_URI          = "uri";     // For JSON based requests only
    public static final String SHREQ_HASHED_TARGET_URI   = "htu";     // For URI based requests only
    public static final String SHREQ_HTTP_METHOD         = "mtd";
    public static final String SHREQ_ISSUED_AT_TIME      = "iat";
    public static final String SHREQ_HEADER_RECORD       = "hdr";
    public static final String SHREQ_HASH_ALG_OVERRIDE   = "hao";
    public static final String SHREQ_JWS_STRING          = "jws";     // For JSON based requests only
    
    public static final String SHREQ_DEFAULT_JSON_METHOD = "POST";
    public static final String SHREQ_DEFAULT_URI_METHOD  = "GET";
    
    public static final String[] HTTP_METHODS            = {"GET", 
                                                            "POST",
                                                            "PUT", 
                                                            "DELETE",
                                                            "PATCH",
                                                            "HEAD",
                                                            "CONNECT"};
    
    static final LinkedHashMap<String,HashAlgorithms> hashAlgorithms = 
                    new LinkedHashMap<String,HashAlgorithms>();
    static {
        hashAlgorithms.put("S256", HashAlgorithms.SHA256);
        hashAlgorithms.put("S384", HashAlgorithms.SHA384);
        hashAlgorithms.put("S512", HashAlgorithms.SHA512);
    }
    
    private static final String HEADER_SYNTAX = "[a-z0-9\\-\\$_\\.]";
    
    static final Pattern HEADER_STRING_ARRAY_SYNTAX = 
            Pattern.compile(HEADER_SYNTAX + "+(," + HEADER_SYNTAX + "+)*");
    
    public static HashAlgorithms getHashAlgorithm(String algorithmId) throws GeneralSecurityException {
        HashAlgorithms algorithm = hashAlgorithms.get(algorithmId);
        if (algorithm == null) {
            throw new GeneralSecurityException("Unknown hash algorithm: " + algorithmId);
        }
        return algorithm;
    }
    
    public static String overridedHashAlgorithm; // Ugly system wide setting
    
    private static byte[] digest(SignatureAlgorithms defaultAlgorithmSource, String data)
    throws IOException, GeneralSecurityException {
        return (overridedHashAlgorithm == null ? 
                defaultAlgorithmSource.getDigestAlgorithm() 
                      :
                getHashAlgorithm(overridedHashAlgorithm))
                    .digest(data.getBytes("utf-8"));
    }
    
    private static JSONObjectWriter setHeader(JSONObjectWriter wr,
                                              LinkedHashMap<String, String> httpHeaderData,
                                              SignatureAlgorithms signatureAlgorithm,
                                              boolean required)
    throws IOException, GeneralSecurityException {
        boolean headerFlag = httpHeaderData != null && !httpHeaderData.isEmpty();
        if ((headerFlag || required) && overridedHashAlgorithm != null) {
            wr.setString(SHREQ_HASH_ALG_OVERRIDE, overridedHashAlgorithm);
        }
        if (headerFlag) {
            StringBuilder headerBlob = new StringBuilder();
            StringBuilder headerList = new StringBuilder();
            boolean next = false;
            for (String header : httpHeaderData.keySet()) {
                headerBlob.append(header)
                          .append(':')
                          .append(httpHeaderData.get(header));
                if (next) {
                    headerBlob.append('\n');
                    headerList.append(',');
                }
                next = true;
                headerList.append(header);
            }
            wr.setArray(SHREQ_HEADER_RECORD)
                .setBinary(digest(signatureAlgorithm, headerBlob.toString()))
                .setString(headerList.toString());
        }
        return wr;
    }
    
    public static JSONObjectWriter createJSONRequestSecInf(String targetUri,
                                                           String targetMethod,
                                                           GregorianCalendar issuetAt,
                                                           LinkedHashMap<String, String> httpHeaderData, 
                                                           SignatureAlgorithms signatureAlgorithm)
    throws IOException, GeneralSecurityException {
        JSONObjectWriter secinf = new JSONObjectWriter()
            .setString(SHREQ_TARGET_URI, normalizeTargetURI(targetUri))

            // If the method is "POST" this element MAY be skipped
            .setDynamic((wr) -> targetMethod == null ?
                    wr : wr.setString(SHREQ_HTTP_METHOD, targetMethod))

            // If "message" already has a "DateTime" object this element MAY be skipped
            .setDynamic((wr) -> issuetAt == null ?
                    wr : wr.setInt53(SHREQ_ISSUED_AT_TIME, issuetAt.getTimeInMillis() / 1000));

        // Optional HTTP headers
        return setHeader(secinf, httpHeaderData, signatureAlgorithm, false);
    }
    
    public static JSONObjectWriter createURIRequestSecInf(String targetUri,
                                                          String targetMethod,
                                                          GregorianCalendar issuetAt,
                                                          LinkedHashMap<String, String> httpHeaderData, 
                                                          SignatureAlgorithms signatureAlgorithm)
    throws IOException, GeneralSecurityException {
        JSONObjectWriter secinf = new JSONObjectWriter()
            .setBinary(SHREQ_HASHED_TARGET_URI, 
                       getDigestedURI(normalizeTargetURI(targetUri), signatureAlgorithm))
    
            // If the method is "GET" this element MAY be skipped
            .setDynamic((wr) -> targetMethod == null ? 
            wr : wr.setString(SHREQ_HTTP_METHOD, targetMethod))
            
            // This element MAY be skipped
            .setDynamic((wr) -> issuetAt == null ?
            wr : wr.setInt53(SHREQ_ISSUED_AT_TIME, issuetAt.getTimeInMillis() / 1000));
    
        // Optional headers
        return setHeader(secinf, httpHeaderData, signatureAlgorithm, true);
    }
    
    static final char[] BIG_HEX = {'0', '1', '2', '3', '4', '5', '6', '7',
                                   '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    
    public static String utf8EscapeUri(String uri) throws IOException {
        StringBuilder escaped = new StringBuilder();
        byte[] utf8 = uri.getBytes("utf-8");
        for (byte b : utf8) {
            if (b < 0) {
                escaped.append('%')
                       .append(BIG_HEX[(b & 0xf0) >> 4])
                       .append(BIG_HEX[b & 0xf]);
            } else {
                escaped.append((char)b);
            }
        }
        return escaped.toString();
    }

    public static String addJwsToTargetUri(String targetUri, String jwsString) {
        return targetUri + (targetUri.contains("?") ?
                '&' : '?') + SHREQSupport.SHREQ_SECINF_LABEL + "=" + jwsString;
    }

    public static String normalizeTargetURI(String uri) throws IOException {
        // Incomplete...
        if (uri.startsWith("https:")) {
            uri = uri.replace(":443/", "/");
        } else {
            uri = uri.replace(":80/", "/");
        }
        return utf8EscapeUri(uri);
    }

    static byte[] getDigestedURI(String alreadyNormalizedUri,
                                 SignatureAlgorithms signatureAlgorithm)
    throws IOException, GeneralSecurityException {
        return digest(signatureAlgorithm, alreadyNormalizedUri);      
    }

    public static String normalizeHeaderArgument(String argument) {
        return argument.trim();
    }

}
