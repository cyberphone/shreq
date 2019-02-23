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

import java.security.GeneralSecurityException;

import java.util.LinkedHashMap;

import java.util.logging.Logger;

abstract class ValidationCore {
    
    String targetUri;
    
    String targetMethod;
    
    static final String REQ_URI = "$reg.uri";
    
    LinkedHashMap<String, String> headerMap;

    protected ValidationCore(String targetUri,
                             String targetMethod,
                             LinkedHashMap<String, String> headerMap) {
        this.targetUri = targetUri;
        this.targetMethod = targetMethod;
        this.headerMap = headerMap;
    }

    protected static Logger logger = Logger.getLogger(ValidationCore.class.getName());

    protected  abstract void validate() throws IOException, GeneralSecurityException;

    String printCoreData() throws IOException {
        StringBuilder coreData = new StringBuilder()
            .append(targetMethod)
            .append(' ')
            .append(targetUri)
            .append('\n');
        for (String header : headerMap.keySet()) {
            coreData.append(header)
                    .append(':')
                    .append(headerMap.get(header))
                    .append('\n');
        }
        return coreData.toString();
    }
    
    void error(String what) throws IOException {
        throw new IOException(what);
    }
}
