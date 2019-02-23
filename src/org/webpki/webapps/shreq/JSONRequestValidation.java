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
import java.util.LinkedHashMap;

import org.webpki.json.JSONObjectReader;

public class JSONRequestValidation extends ValidationCore {
    
    JSONObjectReader message;  // "Message" in the specification

    public JSONRequestValidation(String targetUri,
                                 String targetMethod,
                                 LinkedHashMap<String, String> headerMap,
                                 JSONObjectReader message) {
        super(targetUri, targetMethod, headerMap);
        this.message = message;
    }

    @Override
    protected void validate() throws IOException {
        // 4.2 step 1-4 are already performed
        
        // 4.2:5
        String declaredUri = message.getString(REQ_URI);
        if (declaredUri.equals(targetUri)) {
            error("Declared URI=" + declaredUri + " Actual URI=" + targetUri);
        }
    }


}
