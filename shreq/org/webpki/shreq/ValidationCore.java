/*
 *  Copyright 2018-2020 WebPKI.org (http://webpki.org).
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

import java.security.cert.X509Certificate;

import java.util.Arrays;
import java.util.GregorianCalendar;
import java.util.HashSet;
import java.util.LinkedHashMap;

import java.util.logging.Logger;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.HmacAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;

import org.webpki.jose.JOSEKeyWords;

import org.webpki.jose.jws.JWSDecoder;

import org.webpki.json.JSONArrayReader;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONParser;

import org.webpki.util.Base64URL;

public abstract class ValidationCore {
    
    protected LinkedHashMap<String, String> headerMap;

    protected String jwsProtectedHeaderB64U;

    protected JSONObjectReader jwsProtectedHeader;
    
    protected byte[] jwsPayload;

    protected String jwsSignatureB64U;

    private boolean validationMode;
    
    private ValidationKeyService validationKeyService;
    
    protected String normalizedTargetUri;
    
    protected String targetMethod;
    
    protected GregorianCalendar issuedAt;
    
    protected SignatureAlgorithms signatureAlgorithm;
    
    protected HashAlgorithms hashAlgorithm;  // For digests
    
    protected String keyId;
    
    protected PublicKey publicKey;
    
    protected X509Certificate[] certificatePath;
    
    JSONObjectReader secinf;
    
    JWSDecoder jwsDecoder;
    
    private boolean detached;
    
    private Object cookie;

    protected ValidationCore(String targetUri,
                             String targetMethod,
                             LinkedHashMap<String, String> headerMap) throws IOException {
        this.normalizedTargetUri = SHREQSupport.normalizeTargetURI(targetUri);
        this.headerMap = headerMap;
        for (String method : SHREQSupport.HTTP_METHODS) {
            if (method.equals(targetMethod)) {
                this.targetMethod = targetMethod;
                return;
            }
        }
        error("Unsupported method: " + targetMethod);
    }

    protected static Logger logger = Logger.getLogger(ValidationCore.class.getName());

    protected abstract String defaultMethod();

    protected abstract void validateImplementation() throws IOException, GeneralSecurityException;
    
    public void setCookie(Object cookie) {
        this.cookie = cookie;
    }

    public Object getCookie() {
        return cookie;
    }

    public byte[] getJwsPayload() {
        return jwsPayload;
    }

    public JSONObjectReader getJwsProtectedHeader() {
        return jwsProtectedHeader;
    }

    public JSONObjectReader getSHREQRecord() {
        return secinf;
    }

    public X509Certificate[] getCertificatePath() {
        return certificatePath;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public String getKeyId() {
        return keyId;
    }

    public SignatureAlgorithms getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public GregorianCalendar getIssuedAt() {
        return issuedAt;
    }

    public void validate(ValidationKeyService validationKeyService) throws IOException,
                                                                           GeneralSecurityException {
        this.validationKeyService = validationKeyService;
        validateImplementation();
        secinf.checkForUnread();
        validateSignature();
    }

    public boolean isValidating() {
        return validationMode;
    }
    
    public void enforceTimeStamp(int after, int before) throws IOException {
        if (issuedAt == null) {
            error("Missing time stamp");
        }
        long diff = new GregorianCalendar().getTimeInMillis() - issuedAt.getTimeInMillis();
        if (diff > after || -diff > before) {
            error("Time stamp diff (" + diff/1000.0 + " seconds) is outside of limits");
        }
    }

    public String printCoreData() throws IOException {
        StringBuilder coreData = new StringBuilder("\nReceived Headers:\n")
            .append(targetMethod)
            .append(' ')
            .append(normalizedTargetUri)
            .append('\n');
        for (String header : headerMap.keySet()) {
            coreData.append(header)
                    .append(':')
                    .append(headerMap.get(header))
                    .append('\n');
        }
        coreData.append("\nJWS Protected Header:\n")
                .append(jwsProtectedHeader == null ? 
                                   "NOT AVAILABLE\n" : jwsProtectedHeader.toString())
                .append("\n\"" + SHREQSupport.SHREQ_SECINF_LABEL + "\" Data:\n")
                .append(secinf == null ? "NOT AVAILABLE\n" : secinf.toString());
        coreData.append("\nValidation Key:\n")
                .append(cookie == null ? "NOT AVAILABLE\n" : (String) cookie);
        return coreData.append('\n').toString();
    }

    protected void error(String what) throws IOException {
        throw new IOException(what);
    }

    protected JSONObjectReader commonDataFilter(JSONObjectReader tempSecinf, boolean iatRequired)
    throws IOException, GeneralSecurityException {
        if (tempSecinf.hasProperty(SHREQSupport.SHREQ_HASH_ALG_OVERRIDE)) {
            hashAlgorithm = SHREQSupport.getHashAlgorithm(
                    tempSecinf.getString(SHREQSupport.SHREQ_HASH_ALG_OVERRIDE));
        } else {
            hashAlgorithm = signatureAlgorithm.getDigestAlgorithm();
        }
        String method = 
                tempSecinf.getStringConditional(SHREQSupport.SHREQ_HTTP_METHOD, defaultMethod());
        if (!targetMethod.equals(method)){
            error("Declared Method=" + method + " Actual Method=" + targetMethod);
        }       
        if (iatRequired || tempSecinf.hasProperty(SHREQSupport.SHREQ_ISSUED_AT_TIME)) {
            issuedAt = new GregorianCalendar();
            issuedAt.setTimeInMillis( 
                    // Nobody [as far as I can tell] use fractions but JWT say you can...
                    tempSecinf.getInt53(SHREQSupport.SHREQ_ISSUED_AT_TIME) * 1000);
        }
        if (tempSecinf.hasProperty(SHREQSupport.SHREQ_HEADER_RECORD)) {
            JSONArrayReader array = tempSecinf.getArray(SHREQSupport.SHREQ_HEADER_RECORD);
            byte[] headerDigest = array.getBinary();
            String headerList = array.getString();
            if (array.hasMore()) {
                error("Excess elements in \"" + SHREQSupport.SHREQ_HEADER_RECORD + "\"");
            }
            if (!SHREQSupport.HEADER_STRING_ARRAY_SYNTAX.matcher(headerList).matches()) {
                error("Syntax error in \"" + SHREQSupport.SHREQ_HEADER_RECORD + "\"");
            }
            StringBuilder headerBlob = new StringBuilder();
            HashSet<String> checker = new HashSet<String>();
            boolean next = false;
            for (String header : headerList.split(",")) {
                String argument = headerMap.get(header);
                if (argument == null) {
                    error("Missing header in request: " + header);
                }
                if (next) {
                    headerBlob.append('\n');
                }
                next = true;
                headerBlob.append(header)
                          .append(':')
                          .append(SHREQSupport.normalizeHeaderArgument(argument));
                if (!checker.add(header)) {
                    error("Duplicate header in \"" + SHREQSupport.SHREQ_HEADER_RECORD + "\"");
                }
            }
            if (!Arrays.equals(headerDigest, getDigest(headerBlob.toString()))) {
                error("\"" + SHREQSupport.SHREQ_HEADER_RECORD + "\" digest error");
            }
        }
        return tempSecinf;
    }
    
    protected byte[] getDigest(String data) throws IOException, GeneralSecurityException {
        return hashAlgorithm.digest(data.getBytes("utf-8"));
    }

    // 6.6
    protected void decodeJwsString(String jwsString, boolean detached) throws IOException,
                                                                               GeneralSecurityException {
        this.detached = detached;
        jwsDecoder = new JWSDecoder(jwsString);
        // :1
        int endOfHeader = jwsString.indexOf('.');
        int lastDot = jwsString.lastIndexOf('.');
        if (endOfHeader < 5 || lastDot > jwsString.length() - 5) {
            error("JWS syntax, must be Header.[Payload].Signature");
        }
        if (detached) {
            if (endOfHeader != lastDot - 1) {
                error("JWS syntax, must be Header..Signature");
            }
        } else {
            jwsPayload = Base64URL.decode(jwsString.substring(endOfHeader + 1, lastDot));
        }
        // :2
        jwsProtectedHeaderB64U = jwsString.substring(0, endOfHeader);
        
        // :3-4
        jwsProtectedHeader = JSONParser.parse(Base64URL.decode(jwsProtectedHeaderB64U));

        // :5-6
        jwsSignatureB64U = jwsString.substring(lastDot + 1);

        // Start decoding the JWS header.  Algorithm is the minimum
        String algorithmParam = jwsProtectedHeader.getString(JOSEKeyWords.ALG_JSON);
        if (algorithmParam.equals(JOSEKeyWords.EdDSA)) {
            signatureAlgorithm = jwsSignatureB64U.length() < 100 ? 
                    AsymSignatureAlgorithms.ED25519 : AsymSignatureAlgorithms.ED448;
        } else if (algorithmParam.startsWith("HS")) {
            signatureAlgorithm = 
                    HmacAlgorithms.getAlgorithmFromId(algorithmParam,
                                                     AlgorithmPreferences.JOSE);
        } else {
            signatureAlgorithm = 
                    AsymSignatureAlgorithms.getAlgorithmFromId(algorithmParam, 
                                                               AlgorithmPreferences.JOSE);
        }        
        
        keyId = jwsDecoder.getOptionalKeyId();
        publicKey = jwsDecoder.getOptionalPublicKey();
        certificatePath = jwsDecoder.getOptionalCertificatePath();
    }


    // 6.8
    protected void validateHeaderDigest(JSONObjectReader headerObject) throws IOException {
        error("Not implemented");
    }

    // 6.9
    private void validateSignature() throws IOException, GeneralSecurityException {
        // 4.2:10 or 5.2:5
        
        validationMode = true;
        
        // 6.9:1
        // Unused JWS header elements indicate problems...
        // Disabled, this is a demo :)
        // JWS_Protected_Header.checkForUnread();
        
        // 6.9:2-4
        if (detached) {
            validationKeyService.getSignatureValidator(
                    this,
                    signatureAlgorithm, 
                    certificatePath == null ? 
                                  publicKey : 
                                  certificatePath[0].getPublicKey(),
                    keyId).validate(jwsDecoder, jwsPayload);
        } else {
            validationKeyService.getSignatureValidator(
                    this,
                    signatureAlgorithm, 
                    certificatePath == null ? 
                                  publicKey : 
                                  certificatePath[0].getPublicKey(),
                    keyId).validate(jwsDecoder);
        }
    }
}
