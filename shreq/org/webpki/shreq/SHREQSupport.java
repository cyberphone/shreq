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

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;

public class SHREQSupport {
    
    private SHREQSupport() {}
    
    public static final String SHREQ_LABEL    = "$secinf$";
    
    public static final String URI            = "uri";
    public static final String METHOD         = "mtd";
    public static final String ISSUED_AT_TIME = "iat";
    public static final String JWS            = "jws";
    
    public static final String DEFAULT_JSON_REQUEST_METHOD = "POST";
    public static final String DEFAULT_URI_REQUEST_METHOD  = "GET";
    
    public static class ReceivedJSONRequestHeader {
        String normalizedURI;
        String method;
        GregorianCalendar issuedAt; // May be null
        String jwsString;
        
        public String getNormalizedUri() {
            return normalizedURI;
        }
        
        public String getMethod() {
            return method;
        }
        
        public GregorianCalendar getIssueAt() {
            return issuedAt;
        }
        
        public String getJwsString() {
            return jwsString;
        }
    }
    
    public static JSONObjectWriter createJSONRequestHeader(String uri,
                                                           String method,
                                                           GregorianCalendar issuetAt) throws IOException {
        return new JSONObjectWriter()
            .setString(URI, uri)

            // If the method is "PORT" this element MAY be skipped
            .setDynamic((wr) -> method == null ? wr : wr.setString(METHOD, method))

            // If the "payload" already has a "DateTime" object this element MAY be skipped
            .setDynamic((wr) -> issuetAt == null ? wr : wr.setInt53(ISSUED_AT_TIME, 
                                                                    issuetAt.getTimeInMillis() / 1000));
    }

    public static ReceivedJSONRequestHeader getJSONRequestHeader(JSONObjectReader parsedObject)
    throws IOException {
        JSONObjectReader jsonHeader = parsedObject.getObject(SHREQ_LABEL);
        ReceivedJSONRequestHeader decodedHeader = new ReceivedJSONRequestHeader();
        decodedHeader.normalizedURI = normalizeTargetURI(jsonHeader.getString(URI));
        if (jsonHeader.hasProperty(ISSUED_AT_TIME)) {
            GregorianCalendar issuedAt = new GregorianCalendar();
            issuedAt.setTimeInMillis(jsonHeader.getInt53(ISSUED_AT_TIME) * 1000);
            decodedHeader.issuedAt = issuedAt;
        }
        decodedHeader.method = 
                jsonHeader.getStringConditional(METHOD, 
                                                DEFAULT_JSON_REQUEST_METHOD);
        decodedHeader.jwsString = jsonHeader.getString(JWS);
        jsonHeader.checkForUnread();
        jsonHeader.removeProperty(JWS);
        return decodedHeader;
    }
    
    // 6.7
    public static String normalizeTargetURI(String uri) {
        // To be defined and implemented
        // The famous "no-op" algorithm :)
        return uri;
    }
}
