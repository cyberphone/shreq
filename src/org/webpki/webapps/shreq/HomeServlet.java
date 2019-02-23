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

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class HomeServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
/*
            HTML.output(
                    response,
                    HTML.getHTML(
                            null,
              "<table style=\"max-width=\"300px\">"
            + "<tr><td align=\"center\" style=\"font-weight:bolder;font-size:10pt;font-family:arial,verdana\">JSON Clear Text Signature<br>&nbsp;</td></tr>"
            + "<tr><td align=\"left\"><a href=\""
            + baseurl
            + "/verify\">Verify a JWS-JCS on the server</a></td></tr>"
            + "<tr><td>&nbsp;</td></tr>"
            + "<tr><td align=\"left\"><a href=\""
            + baseurl
            + "/create\">Create a JWS-JCS on the server</a></td></tr>"
            + "<tr><td>&nbsp;</td></tr>"
            + "<tr><td align=\"left\"><a href=\""
            + baseurl
            + "/webcrypto\">Create a JWS-JCS using WebCrypto</a></td></tr>"
            + "<tr><td>&nbsp;</td></tr>"
            + "<tr><td align=\"left\"><a target=\"_blank\" href=\"https://github.com/cyberphone/jws-jcs#combining-detached-jws-with-jcs-json-canonicalization-scheme\">JWS-JCS Documentation</a></td></tr>"
            + "</table>"));
        }
*/


        HTML.standardPage(response, null, new StringBuilder(
            "<div class=\"header\">JSON Clear Text Signature</div>" +
            "<div style=\"padding-top:15pt\">This site permits testing and debugging systems utilizing a " +
            "scheme for clear text JSON signatures tentatively targeted for " +
            "IETF standardization.  For detailed technical information and " +
            "open source code, click on the JWS&#x2022;JCS logotype.</div>" +
            "<div style=\"display:flex;justify-content:center\"><table>" +
            "<tr><td><div class=\"multibtn\" " +
            "onclick=\"document.location.href='create'\" " +
            "title=\"Create JSON signatures\">" +
            "Create JSON Signatures" +
            "</div></td></tr>" +
            "<tr><td><div class=\"multibtn\" " +
            "onclick=\"document.location.href='verify'\" " +
            "title=\"Verify JSON signatures\">" +
            "Verify JSON Signatures" +
            "</div></td></tr>" +
            "<tr><td><div class=\"multibtn\" " +
            "onclick=\"document.location.href='webcrypto'\" " +
            "title=\"&quot;Experimental&quot; - WebCrypto\">" +
            "&quot;Experimental&quot; - WebCrypto" +
            "</div></td></tr>" +
            "</table></div>" +
            "<div class=\"sitefooter\">Privacy/security notice: No user provided data is " +
            "ever stored or logged on the server; it only processes the data and returns the " +
            "result.</div>"));
    }
}
