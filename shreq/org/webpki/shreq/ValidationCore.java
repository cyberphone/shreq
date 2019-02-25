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
import java.security.PublicKey;

import java.util.LinkedHashMap;

import java.util.logging.Logger;


import org.webpki.crypto.SignatureAlgorithms;

import org.webpki.jose.JOSESupport;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONParser;

import org.webpki.util.Base64URL;


public abstract class ValidationCore {
    
    String targetUri;
    
    String targetMethod;
    
    static final String REQ_URI        = "$req.uri";
    static final String REQ_METHOD     = "$req.mtd";
    static final String REQ_HEADER     = "$req.hdr";
    static final String REQ_JWS        = "$req.jws";
    
    static final String DEFAULT_METHOD = "POST";

   
    protected LinkedHashMap<String, String> headerMap;

    protected String jwsProtectedHeaderB64U;

    protected JSONObjectReader JWS_Protected_Header;
    
    protected byte[] JWS_Payload;

    protected byte[] JWS_Signature;

    private boolean validationMode;
    
    private ValidationKeyService validationKeyService;

    protected ValidationCore(String targetUri,
                             String targetMethod,
                             LinkedHashMap<String, String> headerMap) {
        this.targetUri = targetUri;
        this.targetMethod = targetMethod;
        this.headerMap = headerMap;
    }

    protected static Logger logger = Logger.getLogger(ValidationCore.class.getName());

    protected abstract void createJWS_Payload() throws IOException;
    
    protected abstract void validateImplementation() throws IOException, GeneralSecurityException;
    
    public void validate(ValidationKeyService validationKeyService) throws IOException,
                                                                           GeneralSecurityException {
        this.validationKeyService = validationKeyService;
        validateImplementation();
        validateSignature();
    }

    public boolean isValidating() {
        return validationMode;
    }

    public String printCoreData() throws IOException {
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

    protected void error(String what) throws IOException {
        throw new IOException(what);
    }

    // 6.6
    protected void decodeJWS_String(String jwsString) throws IOException {
        // :1
        int endOfHeader = jwsString.indexOf('.');
        int lastDot = jwsString.lastIndexOf('.');
        if (endOfHeader < 5 || endOfHeader != lastDot - 1 || lastDot > jwsString.length() - 5) {
            error("JWS syntax, must be Header..Signature");
        }

        // :2
        jwsProtectedHeaderB64U = jwsString.substring(0, endOfHeader);
        
        // :3-4
        JWS_Protected_Header = JSONParser.parse(Base64URL.decode(jwsProtectedHeaderB64U));
        
        // :5-6
        JWS_Signature = Base64URL.decode(jwsString.substring(lastDot + 1));
    }

    // 6.7
    public static String normalizeTargetURI(String uri) {
        // To be defined and implemented
        // The famous "no-op" algorithm :)
        return uri;
    }

    // 6.8
    protected void validateHeaderDigest(JSONObjectReader headerObject) throws IOException {
        error("Not implemented");
    }

    // 6.9
    private void validateSignature() throws IOException, GeneralSecurityException {
        // 4.2:10 or 5.2:5
        createJWS_Payload();
        
        validationMode = true;
        
        // 6.9:1
        SignatureAlgorithms signatureAlgorithm = JOSESupport.getSignatureAlgorithm(JWS_Protected_Header);
        String keyId = JWS_Protected_Header.hasProperty(JOSESupport.KID_JSON) ?
                JOSESupport.getKeyId(JWS_Protected_Header) : null;
        PublicKey publicKey = JWS_Protected_Header.hasProperty(JOSESupport.JWK_JSON) ?
                JOSESupport.getPublicKey(JWS_Protected_Header) : null;
        if (publicKey != null && signatureAlgorithm.isSymmetric()) {
            throw new GeneralSecurityException("Public key and HMAC algorithm");
        }

        // Unused JWS header elements indicate problems...
        JWS_Protected_Header.checkForUnread();
        
        // 6.9:2-4
        JOSESupport.validateDetachedJwsSignature(
                jwsProtectedHeaderB64U, 
                JWS_Payload,
                JWS_Signature, 
                validationKeyService.getSignatureValidator(signatureAlgorithm, 
                                                           publicKey,
                                                           keyId));
    }
}
