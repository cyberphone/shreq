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
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;

public class JSONRequestValidation extends ValidationCore {
    
    JSONObjectReader message;  // "message" in the specification
    
    public JSONRequestValidation(String targetUri,
                                 String targetMethod,
                                 LinkedHashMap<String, String> headerMap,
                                 JSONObjectReader message) throws IOException {
        super(targetUri, targetMethod, headerMap);
        this.message = message;
    }

    @Override
    protected void validateImplementation() throws IOException, 
                                                   GeneralSecurityException {
        JSONObjectReader temp = message.getObject(SHREQSupport.SHREQ_LABEL);
        String jwsString = temp.getString(SHREQSupport.SHREQ_JWS_STRING);
        decodeJwsString(jwsString, true);

        shreqData = commonDataFilter(temp);

        String normalizedURI = shreqData.getString(SHREQSupport.SHREQ_TARGET_URI);
        if (!normalizedURI.equals(normalizedTargetUri)) {
            error("Declared URI=" + normalizedURI + " Actual URI=" + normalizedTargetUri);
        }
        
        // All but the signature element is signed
        shreqData.removeProperty(SHREQSupport.SHREQ_JWS_STRING);

        JWS_Payload = message.serializeToBytes(JSONOutputFormats.CANONICALIZED);
        
        // However, be nice and restore the signature element after canonicalization
        JSONObjectWriter msg = new JSONObjectWriter(shreqData);
        msg.setupForRewrite(SHREQSupport.SHREQ_JWS_STRING);
        msg.setString(SHREQSupport.SHREQ_JWS_STRING, jwsString);
        shreqData.scanAway(SHREQSupport.SHREQ_JWS_STRING);
    }

    @Override
    protected String defaultMethod() {
        return SHREQSupport.SHREQ_DEFAULT_JSON_METHOD;
    }
}
