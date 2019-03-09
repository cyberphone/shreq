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
import java.net.URLEncoder;
import java.security.KeyPair;
import java.util.GregorianCalendar;
import java.util.LinkedHashMap;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.MACAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.jose.JOSEAsymKeyHolder;
import org.webpki.jose.JOSESupport;
import org.webpki.jose.JOSESymKeyHolder;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;
import org.webpki.shreq.SHREQSupport;
import org.webpki.util.Base64;
import org.webpki.util.DebugFormatter;
import org.webpki.util.PEMDecoder;

public class CurlServlet extends BaseGuiServlet {
    
    private static final long serialVersionUID = 1L;

    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        getSampleData(request);
        StringBuilder html = new StringBuilder(
            "<div class=\"header\">SHREQ Message Creation</div>")

        .append(
                HTML.fancyBox("urirequest", sampleUriRequestUri, 
                        "URI based GET request"))

        .append(
                HTML.fancyBox("jsonrequest", sampleJsonRequestUri, 
                "JSON based POST request"))
        .append(
            "<div>&nbsp;</div>");

        HTML.standardPage(response, null, html);
    }
}
