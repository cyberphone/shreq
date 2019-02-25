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

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONOutputFormats;

public class JSONRequestValidation extends ValidationCore {
    
    JSONObjectReader message;  // "message" in the specification

    public JSONRequestValidation(String targetUri,
                                 String targetMethod,
                                 LinkedHashMap<String, String> headerMap,
                                 JSONObjectReader message) {
        super(targetUri, targetMethod, headerMap);
        this.message = message;
    }

    @Override
    protected void validateImplementation() throws IOException, GeneralSecurityException {
        // 4.2 step 1-6 are already performed
        
        // 4.2:7
        String declaredUri = message.getString(REQ_URI);
        if (!declaredUri.equals(targetUri)) {
            error("Declared URI=" + declaredUri + " Actual URI=" + targetUri);
        }

        // 4.2:8
        String declaredMethod = message.getStringConditional(REQ_METHOD, DEFAULT_METHOD);
        if (!declaredMethod.equals(targetMethod)) {
            error("Declared Method=" + declaredMethod + " Actual Method=" + targetMethod);
        }
        
        // 4.2:9
        decodeJWS_String(message.getString(REQ_JWS));
        
        // 4.2:10
        if (message.hasProperty(REQ_HEADER)) {
            validateHeaderDigest(message.getObject(REQ_HEADER));
        }
        
        // 4.2:11
        message.removeProperty(REQ_JWS);
        
        // 4.2:10-13 are performed in ValidationCore
     }

    @Override
    protected void createJWS_Payload() throws IOException {
        JWS_Payload = message.serializeToBytes(JSONOutputFormats.CANONICALIZED);
    }
}
