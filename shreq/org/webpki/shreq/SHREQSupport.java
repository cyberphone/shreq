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

import java.util.GregorianCalendar;

import org.webpki.crypto.SignatureAlgorithms;

import org.webpki.json.JSONObjectWriter;

public class SHREQSupport {
    
    private SHREQSupport() {}
    
    public static final String SHREQ_LABEL                 = "$secinf$";
    
    public static final String SHREQ_TARGET_URI            = "uri";  // For JSON requests only
    public static final String SHREQ_HASHED_NORMALIZED_URI = "hnu";  // For URI based requests only
    public static final String SHREQ_HTTP_METHOD           = "mtd";
    public static final String SHREQ_ISSUED_AT_TIME        = "iat";
    public static final String SHREQ_JWS_STRING            = "jws";
    public static final String SHREQ_HEADER_RECORD         = "hdr";
    
    public static final String SHREQ_DEFAULT_JSON_METHOD   = "POST";
    public static final String SHREQ_DEFAULT_URI_METHOD    = "GET";
    
    public static final String[] HTTP_METHODS              = {"GET", 
                                                              "POST",
                                                              "PUT", 
                                                              "DELETE",
                                                              "PATCH",
                                                              "HEAD",
                                                              "CONNECT"};
    
    public static JSONObjectWriter createJSONRequestHeader(String uri,
                                                           String method,
                                                           GregorianCalendar issuetAt) throws IOException {
        return new JSONObjectWriter()
            .setString(SHREQ_TARGET_URI, uri)

            // If the method is "POST" this element MAY be skipped
            .setDynamic((wr) -> method == null ? wr : wr.setString(SHREQ_HTTP_METHOD, method))

            // If the "payload" already has a "DateTime" object this element MAY be skipped
            .setDynamic((wr) -> issuetAt == null ? wr : wr.setInt53(SHREQ_ISSUED_AT_TIME, 
                                                                    issuetAt.getTimeInMillis() / 1000));
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

    public static String normalizeTargetURI(String uri) throws IOException {
        // To be fully defined and implemented
        return utf8EscapeUri(uri);
    }

    static byte[] getDigestedAndNormalizedURI(String uri, 
                                              SignatureAlgorithms signatureAlgorithm) throws IOException {
        return signatureAlgorithm.getDigestAlgorithm().digest(normalizeTargetURI(uri).getBytes("utf-8"));
    }

    public static JSONObjectWriter createURIRequestPayload(String targetUri,
                                                           String method,
                                                           GregorianCalendar issuetAt,
                                                           SignatureAlgorithms signatureAlgorithm)
    throws IOException {
        return new JSONObjectWriter()
            .setBinary(SHREQ_HASHED_NORMALIZED_URI, getDigestedAndNormalizedURI(targetUri,
                                                                                signatureAlgorithm))
    
            // If the method is "GET" this element MAY be skipped
            .setDynamic((wr) -> method == null ? wr : wr.setString(SHREQ_HTTP_METHOD, method))
    
            // This element MAY be skipped
            .setDynamic((wr) -> issuetAt == null ? wr : wr.setInt53(SHREQ_ISSUED_AT_TIME, 
                                                                    issuetAt.getTimeInMillis() / 1000));
    }
}
