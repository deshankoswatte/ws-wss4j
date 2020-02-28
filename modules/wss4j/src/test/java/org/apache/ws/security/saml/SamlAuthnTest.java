/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.ws.security.saml;

import java.util.List;

import javax.security.auth.callback.CallbackHandler;

import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.common.CustomSamlAssertionValidator;
import org.apache.ws.security.common.SAML1CallbackHandler;
import org.apache.ws.security.common.SAML2CallbackHandler;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.WSSecSAMLToken;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.apache.ws.security.saml.ext.SAMLParms;
import org.apache.ws.security.util.XMLUtils;
import org.joda.time.DateTime;
import org.w3c.dom.Document;

/**
 * Some tests for SAML Authentication Assertions
 */
public class SamlAuthnTest extends org.junit.Assert {
    private static final org.slf4j.Logger LOG = 
        org.slf4j.LoggerFactory.getLogger(SamlAuthnTest.class);
    private WSSecurityEngine secEngine = new WSSecurityEngine();
    
    public SamlAuthnTest() {
        WSSConfig config = WSSConfig.getNewInstance();
        config.setValidator(WSSecurityEngine.SAML_TOKEN, new CustomSamlAssertionValidator());
        config.setValidator(WSSecurityEngine.SAML2_TOKEN, new CustomSamlAssertionValidator());
        secEngine.setWssConfig(config);
    }
    
    @org.junit.Test
    public void testSAML1AuthnAssertion() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");
        
        createAndVerifyMessage(callbackHandler, true);
    }
    
    @org.junit.Test
    public void testSAML2AuthnAssertion() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");
        
        createAndVerifyMessage(callbackHandler, true);
    }
    
    @org.junit.Test
    public void testSAML1FutureAuthnInstant() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");
        
        callbackHandler.setAuthenticationInstant(new DateTime().plusMinutes(70));
        
        createAndVerifyMessage(callbackHandler, false);
    }
    
    @org.junit.Test
    public void testSAML2FutureAuthnInstant() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");
        
        callbackHandler.setAuthenticationInstant(new DateTime().plusMinutes(70));
        
        createAndVerifyMessage(callbackHandler, false);
    }
    
    @org.junit.Test
    public void testSAML2StaleSessionNotOnOrAfter() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");
        
        callbackHandler.setSessionNotOnOrAfter(new DateTime().minusMinutes(70));
        
        createAndVerifyMessage(callbackHandler, false);
    }
    
    @org.junit.Test
    public void testSAML1ValidSubjectLocality() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");
        
        callbackHandler.setSubjectLocality("127.0.0.1", "xyz.ws.apache.org");
        
        createAndVerifyMessage(callbackHandler, true);
    }
    
    @org.junit.Test
    public void testSAML2ValidSubjectLocality() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");
        
        callbackHandler.setSubjectLocality("127.0.0.1", "xyz.ws.apache.org");
        
        createAndVerifyMessage(callbackHandler, true);
    }
    
    @org.junit.Test
    public void testSAML1InvalidSubjectLocality() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");
        
        callbackHandler.setSubjectLocality("xyz.ws.apache.org", "xyz.ws.apache.org");
        
        createAndVerifyMessage(callbackHandler, false);
    }
    
    @org.junit.Test
    public void testSAML2InalidSubjectLocality() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");
        
        callbackHandler.setSubjectLocality("xyz.ws.apache.org", "xyz.ws.apache.org");
        
        createAndVerifyMessage(callbackHandler, false);
    }
    
    private void createAndVerifyMessage(
        CallbackHandler samlCallbackHandler, boolean success
    ) throws Exception {
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(samlCallbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, assertion, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(unsignedDoc);
            LOG.debug(outputString);
        }
        
        try {
            verify(unsignedDoc);
            if (!success) {
                fail("Failure expected in processing the SAML assertion");
            }
        } catch (WSSecurityException ex) {
            assertTrue(!success);
            assertTrue(ex.getMessage().contains("SAML token security failure"));
        }
    }
    
    /**
     * Verifies the soap envelope
     * <p/>
     * 
     * @param envelope 
     * @throws Exception Thrown when there is a problem in verification
     */
    private List<WSSecurityEngineResult> verify(Document doc) throws Exception {
        List<WSSecurityEngineResult> results = 
            secEngine.processSecurityHeader(doc, null, null, null);
        String outputString = 
            XMLUtils.PrettyDocumentToString(doc);
        assertTrue(outputString.indexOf("counter_port_type") > 0 ? true : false);
        return results;
    }
    
}
