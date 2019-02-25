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

import java.util.LinkedHashMap;

public class URIRequestValidation extends ValidationCore {
    
    static final String QUERY_STRING = REQ_JWS + "=";
    static final int    QUERY_LENGTH = QUERY_STRING.length();

    public URIRequestValidation(String targetUri,
                                String targetMethod,
                                LinkedHashMap<String, String> headerMap) {
        super(targetUri, targetMethod, headerMap);
    }


    @Override
    protected void createJWS_Payload() throws IOException {
        JWS_Payload = (targetMethod + "," + targetUri).getBytes("utf-8");
    }


    @Override
    protected void validateImplementation() throws IOException,
                                                   GeneralSecurityException {
        // 5.2:3-4
        int i = targetUri.indexOf(QUERY_STRING);
        if (i < 10) {
            error("Missing '" + QUERY_STRING + "'");
        }
        int next = targetUri.indexOf('&', i);
        String jwsString;
        if (next < 0) {
            jwsString = targetUri.substring(i + QUERY_LENGTH);
            targetUri = targetUri.substring(0, i - 1);
        } else {
            jwsString = targetUri.substring(i + QUERY_LENGTH, next);
            targetUri = targetUri.substring(0, i) + targetUri.substring(next + 1);
        }
        decodeJWS_String(jwsString);
        
        // 5.2:5
        // TBD
        
        // 5.2:6-7 are performed in ValidationCore
    }

}
