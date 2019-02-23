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

import java.util.Enumeration;
import java.util.LinkedHashMap;

import java.util.logging.Logger;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.json.JSONParser;

import org.webpki.webutil.ServletUtil;

public class RequestServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    
    private static final String CONTENT_TYPE   = "Content-Type";
    private static final String CONTENT_LENGTH = "Content-Length";
    
    private static final String JSON_CONTENT   = "application/json";

    static Logger logger = Logger.getLogger(RequestServlet.class.getName());

    @Override
    public void service(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        ValidationCore validationCore = null;

        // Recreate the Target URI
        String targetUri = request.getScheme() + "://" +
                request.getServerName() + 
                ("http".equals(request.getScheme()) && request.getServerPort() == 80 ||
                 "https".equals(request.getScheme()) && request.getServerPort() == 443 ? 
                 "" : ":" + request.getServerPort()) +
                request.getRequestURI() +
               (request.getQueryString() == null ? "" : "?" + request.getQueryString());

        // Get the Target Method
        String targetMethod = request.getMethod().toUpperCase();
        
        // Collect HTTP Headers in a Lowercase Format
        LinkedHashMap<String, String> headerMap = new LinkedHashMap<String, String>();
        @SuppressWarnings("unchecked")
        Enumeration<String> headers = request.getHeaderNames();
        while (headers.hasMoreElements()) {
            String header = headers.nextElement();
            headerMap.put(header.toLowerCase(), request.getHeader(header));
        }
        
        // Now, it starts specification wise :-)
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
            validationCore.validate();
            
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
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.setHeader(CONTENT_TYPE, "text/plain;utf-8");
            ServletOutputStream os = response.getOutputStream();
            os.println("ERROR: " + e.getMessage());
            if (validationCore == null) {
                os.println("Validation context not available");
            } else {
                os.print(validationCore.printCoreData());
            }
            response.flushBuffer();
        }
    }
}
