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
import java.security.PublicKey;

import java.util.Enumeration;
import java.util.LinkedHashMap;

import java.util.logging.Logger;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.MACAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;

import org.webpki.jose.JOSEAsymSignatureValidator;
import org.webpki.jose.JOSEHmacValidator;
import org.webpki.jose.JOSESupport;

import org.webpki.json.JSONParser;

import org.webpki.shreq.JSONRequestValidation;
import org.webpki.shreq.SHREQSupport;
import org.webpki.shreq.URIRequestValidation;
import org.webpki.shreq.ValidationCore;
import org.webpki.shreq.ValidationKeyService;

import org.webpki.webutil.ServletUtil;

public abstract class BaseRequestServlet extends HttpServlet implements ValidationKeyService {

    private static final long serialVersionUID = 1L;
    
    private static final String CONTENT_TYPE   = "Content-Type";
    private static final String CONTENT_LENGTH = "Content-Length";
    
    private static final String JSON_CONTENT   = "application/json";

    static Logger logger = Logger.getLogger(BaseRequestServlet.class.getName());

    protected abstract boolean externallyConfigured(); 
    
    static String getStackTrace(Exception e) {
        StringBuffer error = new StringBuffer("Stack trace:\n")
            .append(e.getClass().getName())
            .append(": ")
            .append(e.getMessage());
        StackTraceElement[] st = e.getStackTrace();
        int length = st.length;
        if (length > 20) {
            length = 20;
        }
        for (int i = 0; i < length; i++) {
          error.append("\n  at " + st[i].toString());
        }
        return error.toString();
    }
    
    static String getUrlFromRequest(HttpServletRequest request) {
        return request.getScheme() + "://" +
                request.getServerName() + 
                ("http".equals(request.getScheme()) && request.getServerPort() == 80 ||
                 "https".equals(request.getScheme()) && request.getServerPort() == 443 ? 
                 "" : ":" + request.getServerPort()) +
                request.getRequestURI() +
               (request.getQueryString() == null ? "" : "?" + request.getQueryString());
    }
    
    protected boolean enforceTimeStamp() {
        return false;
    }
    
    @Override
    public void service(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        ValidationCore validationCore = null;

        // Get the Target Method (4.2:1 , 5.2:1)
        String targetMethod = request.getMethod();
        
        // Recreate the normalized Target URI (4.2:2 , 5.2:2)
        String targetUri = SHREQSupport.normalizeTargetURI(getUrlFromRequest(request));

        // Collect HTTP Headers in a Lowercase Format
        LinkedHashMap<String, String> headerMap = new LinkedHashMap<String, String>();
        @SuppressWarnings("unchecked")
        Enumeration<String> headers = request.getHeaderNames();
        while (headers.hasMoreElements()) {
            String header = headers.nextElement();
            headerMap.put(header.toLowerCase(), request.getHeader(header));
        }
        
        try {

            // 3. Determining Request Type
            if (request.getHeader(CONTENT_LENGTH) == null) {

                // 5.2 URI Request
                if (request.getHeader(CONTENT_TYPE) != null) {
                    throw new IOException("Unexpected: " + CONTENT_TYPE);
                }
                validationCore = new URIRequestValidation(targetUri,
                                                          targetMethod, 
                                                          headerMap);
            } else {

                // 4.2 JSON Request
                if (!JSON_CONTENT.equals(request.getHeader(CONTENT_TYPE))) {
                    throw new IOException(CONTENT_TYPE + "=" + request.getHeader(CONTENT_TYPE));
                }
                validationCore = new JSONRequestValidation(targetUri,
                                                           targetMethod,
                                                           headerMap,
                                                           JSONParser.parse(ServletUtil.getData(request)));
            }
            
            // Core Request Data Successfully Collected - Validate!
            validationCore.validate(this);
            
            // Optional test
            if (enforceTimeStamp()) {
                validationCore.enforceTimeStamp(5);  // +-5 minutes
            }

            // No exceptions => We did it!
            response.resetBuffer();
            response.setStatus(HttpServletResponse.SC_OK);
            response.setHeader(CONTENT_TYPE, "text/plain;utf-8");
            ServletOutputStream os = response.getOutputStream();
            os.println("SUCCESS");
            os.print(validationCore.printCoreData());
            response.flushBuffer();

        } catch (Exception e) {
            // Houston, we got a problem...
            response.resetBuffer();
            response.setStatus(validationCore == null || !validationCore.isValidating() ?
                HttpServletResponse.SC_BAD_REQUEST : HttpServletResponse.SC_UNAUTHORIZED);
            response.setHeader(CONTENT_TYPE, "text/plain;utf-8");
            ServletOutputStream os = response.getOutputStream();
            os.println(getStackTrace(e));
            if (validationCore == null) {
                os.println("Validation context not available");
            } else {
                os.print(validationCore.printCoreData());
            }
            response.flushBuffer();
        }
    }

    void extConfError() throws IOException {
        throw new IOException("'" + BaseGuiServlet.EXTCONFREQ +
                              "' only supports requests with in-lined asymmetric JWKs");
    }

    @Override
    public JOSESupport.CoreSignatureValidator getSignatureValidator(SignatureAlgorithms signatureAlgorithm,
                                                                    PublicKey publicKey, 
                                                                    String keyId)
    throws IOException, GeneralSecurityException {
        if (signatureAlgorithm.isSymmetric()) {
            if (externallyConfigured()) {
                extConfError();
            }
            return new JOSEHmacValidator(SHREQService.predefinedSecretKeys
                    .get(signatureAlgorithm.getAlgorithmId(AlgorithmPreferences.JOSE)),
                                         (MACAlgorithms) signatureAlgorithm);
        }
        PublicKey validationKey;
        if (externallyConfigured()) {
            if (publicKey == null) {
                extConfError();
            }
            validationKey = publicKey;
        } else {
            // Lookup predefined validation key
            validationKey = SHREQService.predefinedKeyPairs
        .get(signatureAlgorithm.getAlgorithmId(AlgorithmPreferences.JOSE)).getPublic();
            if (publicKey != null && !publicKey.equals(validationKey)) {
                throw new GeneralSecurityException("In-lined JWK differs from predefined");
            }
        }
        return new JOSEAsymSignatureValidator(validationKey, 
                                              (AsymSignatureAlgorithms)signatureAlgorithm);
    }
}
