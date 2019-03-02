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
                                 JSONObjectReader message) {
        super(targetUri, targetMethod, headerMap);
        this.message = message;
    }

    @Override
    protected void validateImplementation() throws IOException, 
                                                   GeneralSecurityException {
        // 4.2 step 1-6 are already performed
        
        // 4.2:7
        shreqData = message.getObject(SHREQSupport.SHREQ_LABEL);

        decodeJwsString(shreqData.getString(SHREQSupport.JWS), true);

        String normalizedURI =
                SHREQSupport.normalizeTargetURI(shreqData.getString(SHREQSupport.URI));
        if (!normalizedURI.equals(targetUri)) {
            error("Declared URI=" + normalizedURI + " Actual URI=" + targetUri);
        }

        JSONObjectReader save = shreqData.clone();
        shreqData.removeProperty(SHREQSupport.JWS);
        shreqData = save;

        JWS_Payload = message.serializeToBytes(JSONOutputFormats.CANONICALIZED);
        
        JSONObjectWriter msg = new JSONObjectWriter(message);
        msg.setupForRewrite(SHREQSupport.SHREQ_LABEL);
        msg.setObject(SHREQSupport.SHREQ_LABEL, shreqData);
    }

    @Override
    protected String defaultMethod() {
        return SHREQSupport.DEFAULT_JSON_REQUEST_METHOD;
    }
}
