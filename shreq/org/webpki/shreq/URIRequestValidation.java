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

import org.webpki.json.JSONParser;

import org.webpki.util.ArrayUtil;

public class URIRequestValidation extends ValidationCore {
    
    static final String QUERY_STRING = SHREQSupport.SHREQ_LABEL + "=";
    static final int    QUERY_LENGTH = QUERY_STRING.length();

    public URIRequestValidation(String targetUri,
                                String targetMethod,
                                LinkedHashMap<String, String> headerMap) throws IOException {
        super(targetUri, targetMethod, headerMap);
    }

    @Override
    protected void validateImplementation() throws IOException,
                                                   GeneralSecurityException {
        // 5.2:3-4
        int i = targetUri.indexOf(QUERY_STRING);
        if (i < 10) {
            error("URI lacks a signature ( " + QUERY_STRING + " ) element");
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

        decodeJwsString(jwsString, false);
        shreqData = JSONParser.parse(JWS_Payload);

        if (!ArrayUtil.compare(shreqData.getBinary(SHREQSupport.SHREQ_HASHED_NORMALIZED_URI),
                               SHREQSupport.getDigestedAndNormalizedURI(targetUri,
                                                                        signatureAlgorithm))) {
            error("URI mismatch");
        }
    }

    @Override
    protected String defaultMethod() {
        return SHREQSupport.SHREQ_DEFAULT_URI_METHOD;
    }

}
