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

import javax.servlet.ServletException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CurlServlet extends BaseGuiServlet {
    
    private static final long serialVersionUID = 1L;

    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        getSampleData(request);
        StringBuilder html = new StringBuilder(
            "<div class=\"header\">CURL/Browser Online Testing</div>")

        .append(
            HTML.fancyBox("urirequestbrowser", sampleUriRequestUri, 
                "URI based GET request which can be directly accessed by a <b>Browser</b>"))

        .append(
            HTML.fancyBox("urirequest", "curl " + sampleUriRequestUri, 
                "URI based GET request accessed through <b>CURL</b>"))

        .append(
            HTML.fancyBox("jsonrequest", "curl" +
                          " -H content-type:application/json" +
                          " -d &quot;" + sampleJsonRequest_CURL + "&quot; " +
                          sampleJsonRequestUri, 
                "JSON based POST request accessed through <b>CURL</b>"))

        .append(
            HTML.fancyBox("jsonrequest2", "curl" +
                          " -X PUT" +
                          " -H x-debug:full" +
                          " -H content-type:application/json" +
                          " -d &quot;" + sampleJsonRequest_CURL_Header_PUT + "&quot; " +
                          sampleJsonRequestUri, 
                "JSON based PUT request plus HTTP header variable accessed through <b>CURL</b>"))

        .append(
             "<div style=\"margin-top:20pt\">CURL: " +
             "<a href=\"https://curl.haxx.se/\">https://curl.haxx.se/</a></div>" +
             "<div style=\"margin-top:10pt\">Note that these tests depend on the preconfigured keys " +
             "used by this Web application (one specific key for each signature algorithm). " +
             "You can create compatible requests using the <a href=\"create\">create</a> application.</div>");

        HTML.standardPage(response, null, html);
    }
}
