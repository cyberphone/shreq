/*
 *  Copyright 2006-2018 WebPKI.org (http://webpki.org).
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

import java.util.logging.Logger;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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
        String method = request.getMethod().toUpperCase();
        logger.info("Method=" + method);
        Enumeration<String> headers = request.getHeaderNames();
        while (headers.hasMoreElements()) {
            String header = headers.nextElement();
            logger.info(header + ":" + request.getHeader(header));
        }
        boolean validation = false;
        try {
            // Check headers - Determine request type
            if (request.getHeader(CONTENT_LENGTH) == null) {
                // No body?
                if (request.getHeader(CONTENT_TYPE) != null) {
                    throw new IOException("Unexpected: " + CONTENT_TYPE);
                }
            } else {
                // Body assumed
                int length = request.getContentLength();
                if (!JSON_CONTENT.equals(request.getHeader(CONTENT_TYPE))) {
                    throw new IOException(CONTENT_TYPE + "=" + request.getHeader(CONTENT_TYPE));
                }
            }
            String uri = request.getScheme() + "://" +
                    request.getServerName() + 
                    ("http".equals(request.getScheme()) && request.getServerPort() == 80 || "https".equals(request.getScheme()) && request.getServerPort() == 443 ? "" : ":" + request.getServerPort() ) +
                    request.getRequestURI() +
                   (request.getQueryString() != null ? "?" + request.getQueryString() : "");
            logger.info(uri);
        } catch (Exception e) {
            response.resetBuffer();
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.setHeader("Content-Type", "text/plain");
            response.getOutputStream().print(e.getMessage());
            response.flushBuffer();
        }
    }
}
