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
import java.util.logging.Logger;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.shreq.SHREQSupport;

public class BaseGuiServlet extends HttpServlet {

    static Logger logger = Logger.getLogger(BaseGuiServlet.class.getName());

    private static final long serialVersionUID = 1L;

    // HTML form arguments
    static final String JSON_PAYLOAD       = "json";

    static final String JWS_VALIDATION_KEY = "vkey";
    
    static final String TARGET_URI         = "uri";
    
    static final String HTTP_METHOD        = "mtd";

    static final String OPT_HEADERS        = "hdrs";

    static final String PRM_JWS_EXTRA      = "xtra";

    static final String PRM_SECRET_KEY     = "sec";

    static final String PRM_PRIVATE_KEY    = "priv";

    static final String PRM_CERT_PATH      = "cert";

    static final String PRM_ALGORITHM      = "alg";

    static final String PRM_SCHEME         = "scheme";

    static final String FLG_CERT_PATH      = "cerflg";
    static final String FLG_JWK_INLINE     = "jwkflg";
    static final String FLG_DEF_METHOD     = "defmtd";
    static final String FLG_IAT_PRESENT    = "iatflg";
    static final String FLG_HEADERS        = "hdrflg";
    
    static final String DEFAULT_ALGORITHM   = "ES256";
    static final String DEFAULT_JSON_METHOD = "POST";
    static final String DEFAULT_URI_METHOD  = "GET";
    
    static final String EXTCONFREQ             = "/extconfreq";
    static final String PRECONFREQ             = "/preconfreq";
  
    static String sampleRequest;
    
    static final String TEST_MESSAGE = 
            "{\n" +
            "  \"statement\": \"Hello signed world!\",\n" +
            "  \"otherProperties\": [2e+3, true]\n" +
            "}";
    
    static String _defaultTargetUri;
    
    static String getDefaultUri(HttpServletRequest request) {
        if (_defaultTargetUri == null) {
            synchronized(CreateServlet.class) {
                String url = BaseRequestServlet.getUrlFromRequest(request);
                _defaultTargetUri = url.substring(0, url.indexOf("/shreq/") + 6) +
                        PRECONFREQ + "?id=456";
            }
        }
        return _defaultTargetUri;
    }
    
    static class SelectMethod {

        StringBuilder html = new StringBuilder("<select name=\"" +
                HTTP_METHOD + "\" id=\"" + HTTP_METHOD + "\">");
        
        SelectMethod() {
            for (String method : SHREQSupport.HTTP_METHODS) {
                html.append("<option value=\"")
                    .append(method)
                    .append("\"")
                    .append(method.equals("POST") ? " selected>" : ">")
                    .append(method)
                    .append("</option>");
            }
        }

        @Override
        public String toString() {
            return html.append("</select>").toString();
        }
    }

    class SelectAlg {

        String preSelected;
        StringBuilder html = new StringBuilder("<select name=\"" +
                PRM_ALGORITHM + "\" id=\"" +
                PRM_ALGORITHM + "\" onchange=\"algChange(this.value)\">");
        
        SelectAlg(String preSelected) {
            this.preSelected = preSelected;
        }

        SelectAlg add(SignatureAlgorithms algorithm) throws IOException {
            String algId = algorithm.getAlgorithmId(AlgorithmPreferences.JOSE);
            html.append("<option value=\"")
                .append(algId)
                .append("\"")
                .append(algId.equals(preSelected) ? " selected>" : ">")
                .append(algId)
                .append("</option>");
            return this;
        }

        @Override
        public String toString() {
            return html.append("</select>").toString();
        }
    }
    
    StringBuilder checkBox(String idName, String text, boolean checked, String onchange) {
        StringBuilder html = new StringBuilder("<div style=\"display:flex;align-items:center\"><input type=\"checkbox\" id=\"")
            .append(idName)
            .append("\" name=\"")
            .append(idName)
            .append("\"");
        if (checked) {
            html.append(" checked");
        }
        if (onchange != null) {
            html.append(" onchange=\"")
                .append(onchange)
                .append("\"");
        }
        html.append("><div style=\"display:inline-block\">")
            .append(text)
            .append("</div></div>");
        return html;
    }

    StringBuilder radioButton(String name, String text, String value, boolean checked, String onchange) {
        StringBuilder html = new StringBuilder("<div style=\"display:flex;align-items:center\"><input type=\"radio\" name=\"")
            .append(name)
            .append("\" value=\"")
            .append(value)
            .append("\"");
        if (checked) {
            html.append(" checked");
        }
        if (onchange != null) {
            html.append(" onchange=\"")
                .append(onchange)
                .append("\"");
        }
        html.append("><div style=\"display:inline-block\">")
            .append(text)
            .append("</div></div>");
        return html;
    }
    
    StringBuilder parameterBox(String header, StringBuilder body) {
        return new StringBuilder(
            "<div style=\"display:flex;justify-content:center;margin-top:20pt\">" +
              "<div class=\"sigparmbox\">" +
                "<div style=\"display:flex;justify-content:center\">" +
                  "<div class=\"sigparmhead\">")
        .append(header)
        .append(
                  "</div>" +
                "</div>")
        .append(body)
        .append(
              "</div>" +
            "</div>");      
    }

    StringBuilder getRequestParameters() {
        return parameterBox("Request Parameters", 
            new StringBuilder()
            .append(
                "<div style=\"display:flex;align-items:center\">")
                .append(new SelectMethod().toString())
           .append(
               "<div style=\"display:inline-block;padding:0 10pt 0 5pt\">HTTP Method</div>" +
               "<div class=\"defbtn\" onclick=\"restoreRequestDefaults()\">Restore&nbsp;defaults</div></div>")
           .append(radioButton(PRM_SCHEME, "JSON based request", "true", true, "requestChange(true)"))
           .append(radioButton(PRM_SCHEME, "URI based request", "false", false, "requestChange(false)"))
           .append(checkBox(FLG_HEADERS, "Include HTTP headers as well", 
                                 false, "headerFlagChange(this.checked)")));
    }

    String getParameter(HttpServletRequest request, String parameter) throws IOException {
        String string = request.getParameter(parameter);
        if (string == null) {
            throw new IOException("Missing data for: "+ parameter);
        }
        return string.trim();
    }
    
    byte[] getBinaryParameter(HttpServletRequest request, String parameter) throws IOException {
        return getParameter(request, parameter).getBytes("utf-8");
    }

    String getTextArea(HttpServletRequest request, String name) throws IOException {
        String string = getParameter(request, name);
        StringBuilder s = new StringBuilder();
        for (char c : string.toCharArray()) {
            if (c != '\r') {
                s.append(c);
            }
        }
        return s.toString();
    }
}
