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

package org.apache.ws.security.message;

import java.util.ArrayList;
import java.util.List;

import javax.security.auth.callback.CallbackHandler;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.cache.MemoryReplayCache;
import org.apache.ws.security.common.KeystoreCallbackHandler;
import org.apache.ws.security.common.SAML2CallbackHandler;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.common.UsernamePasswordCallbackHandler;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.apache.ws.security.saml.ext.SAMLParms;
import org.apache.ws.security.saml.ext.bean.ConditionsBean;
import org.apache.ws.security.saml.ext.builder.SAML2Constants;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.ws.security.util.XMLUtils;
import org.apache.ws.security.validate.SamlAssertionValidator;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Some test-cases for replay attacks.
 */
public class ReplayTest extends org.junit.Assert {
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(ReplayTest.class);
    
    private CallbackHandler callbackHandler = new KeystoreCallbackHandler();
    private Crypto crypto = null;
    
    public ReplayTest() throws Exception {
        crypto = CryptoFactory.getInstance();
    }

    @org.junit.Test
    public void testReplayedTimestamp() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        WSSecTimestamp timestamp = new WSSecTimestamp();
        timestamp.setTimeToLive(300);
        Document createdDoc = timestamp.build(doc, secHeader);
        
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        
        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        WSEncryptionPart encP =
            new WSEncryptionPart(
                "Timestamp", WSConstants.WSU_NS, "");
        parts.add(encP);
        builder.setParts(parts);
        
        builder.prepare(createdDoc, crypto, secHeader);
        
        List<javax.xml.crypto.dsig.Reference> referenceList = 
            builder.addReferencesToSign(parts, secHeader);

        builder.computeSignature(referenceList, false, null);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(createdDoc);
            LOG.debug(outputString);
        }
        
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        RequestData data = new RequestData();
        data.setWssConfig(wssConfig);
        data.setCallbackHandler(callbackHandler);
        data.setTimestampReplayCache(new MemoryReplayCache());
        
        // Successfully verify timestamp
        verify(createdDoc, wssConfig, data);
        
        // Now try again - a replay attack should be detected
        try {
            verify(createdDoc, wssConfig, data);
            fail("Expected failure on a replay attack");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.INVALID_SECURITY); 
        }   
    }
    
    @org.junit.Test
    public void testReplayedTimestampBelowSignature() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        WSSecTimestamp timestamp = new WSSecTimestamp();
        timestamp.setTimeToLive(300);
        Document createdDoc = timestamp.build(doc, secHeader);
        
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        
        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        WSEncryptionPart encP =
            new WSEncryptionPart(
                "Timestamp", WSConstants.WSU_NS, "");
        parts.add(encP);
        builder.setParts(parts);
        
        builder.build(createdDoc, crypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(createdDoc);
            LOG.debug(outputString);
        }
        
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        RequestData data = new RequestData();
        data.setWssConfig(wssConfig);
        data.setCallbackHandler(callbackHandler);
        data.setTimestampReplayCache(new MemoryReplayCache());
        
        // Successfully verify timestamp
        verify(createdDoc, wssConfig, data);
        
        // Now try again - a replay attack should be detected
        try {
            verify(createdDoc, wssConfig, data);
            fail("Expected failure on a replay attack");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.INVALID_SECURITY); 
        }   
    }
    
    @org.junit.Test
    public void testReplayedTimestampNoExpires() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        WSSecTimestamp timestamp = new WSSecTimestamp();
        timestamp.setTimeToLive(0);
        Document createdDoc = timestamp.build(doc, secHeader);
        
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        
        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        WSEncryptionPart encP =
            new WSEncryptionPart(
                "Timestamp", WSConstants.WSU_NS, "");
        parts.add(encP);
        builder.setParts(parts);
        
        builder.prepare(createdDoc, crypto, secHeader);
        
        List<javax.xml.crypto.dsig.Reference> referenceList = 
            builder.addReferencesToSign(parts, secHeader);

        builder.computeSignature(referenceList, false, null);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(createdDoc);
            LOG.debug(outputString);
        }
        
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        RequestData data = new RequestData();
        data.setWssConfig(wssConfig);
        data.setCallbackHandler(callbackHandler);
        data.setTimestampReplayCache(new MemoryReplayCache());
        
        // Successfully verify timestamp
        verify(createdDoc, wssConfig, data);
        
        // Now try again - a replay attack should be detected
        try {
            verify(createdDoc, wssConfig, data);
            fail("Expected failure on a replay attack");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.INVALID_SECURITY); 
        }   
    }
    
    @org.junit.Test
    public void testReplayedUsernameToken() throws Exception {
        WSSecUsernameToken builder = new WSSecUsernameToken();
        builder.setUserInfo("wernerd", "verySecret");
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        RequestData data = new RequestData();
        data.setCallbackHandler(new UsernamePasswordCallbackHandler());
        data.setWssConfig(wssConfig);
        data.setNonceReplayCache(new MemoryReplayCache());
        
        // Successfully verify UsernameToken
        verify(signedDoc, wssConfig, data);
        
        // Now try again - a replay attack should be detected
        try {
            verify(signedDoc, wssConfig, data);
            fail("Expected failure on a replay attack");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.INVALID_SECURITY); 
        }   
    }
    
    /**
     * Test that creates, sends and processes an unsigned SAML 2 authentication assertion. This
     * is just a sanity test to make sure that it is possible to send the SAML token twice, as
     * no "OneTimeUse" Element is defined there is no problem with replaying it.
     * with a OneTimeUse Element
     */
    @org.junit.Test
    public void testReplayedSAML2() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        
        ConditionsBean conditions = new ConditionsBean();
        conditions.setTokenPeriodMinutes(5);
            
        callbackHandler.setConditions(conditions);
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper samlAssertion = new AssertionWrapper(samlParms);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, samlAssertion, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = XMLUtils.PrettyDocumentToString(unsignedDoc);
            LOG.debug(outputString);
        }
        
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        SamlAssertionValidator assertionValidator = new SamlAssertionValidator();
        assertionValidator.setRequireBearerSignature(false);
        wssConfig.setValidator(WSSecurityEngine.SAML_TOKEN, assertionValidator);
        wssConfig.setValidator(WSSecurityEngine.SAML2_TOKEN, assertionValidator);
        
        RequestData data = new RequestData();
        data.setWssConfig(wssConfig);
        data.setCallbackHandler(callbackHandler);
        data.setSamlOneTimeUseReplayCache(new MemoryReplayCache());
        
        // Successfully verify SAML Token
        verify(unsignedDoc, wssConfig, data);
        
        // Now try again - this should work fine as well
        verify(unsignedDoc, wssConfig, data);
    }
    
    /**
     * Test that creates, sends and processes an unsigned SAML 2 authentication assertion
     * with a OneTimeUse Element
     */
    @org.junit.Test
    public void testReplayedSAML2OneTimeUse() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        
        ConditionsBean conditions = new ConditionsBean();
        conditions.setTokenPeriodMinutes(5);
        conditions.setOneTimeUse(true);
            
        callbackHandler.setConditions(conditions);
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper samlAssertion = new AssertionWrapper(samlParms);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, samlAssertion, secHeader);

        String outputString = 
            XMLUtils.PrettyDocumentToString(unsignedDoc);
        assertTrue(outputString.contains("OneTimeUse"));
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        SamlAssertionValidator assertionValidator = new SamlAssertionValidator();
        assertionValidator.setRequireBearerSignature(false);
        wssConfig.setValidator(WSSecurityEngine.SAML_TOKEN, assertionValidator);
        wssConfig.setValidator(WSSecurityEngine.SAML2_TOKEN, assertionValidator);
        
        RequestData data = new RequestData();
        data.setWssConfig(wssConfig);
        data.setCallbackHandler(callbackHandler);
        data.setSamlOneTimeUseReplayCache(new MemoryReplayCache());
        
        // Successfully verify SAML Token
        verify(unsignedDoc, wssConfig, data);
        
        // Now try again - a replay attack should be detected
        try {
            verify(unsignedDoc, wssConfig, data);
            fail("Expected failure on a replay attack");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.INVALID_SECURITY); 
        }
    }
    
    /**
     * Verifies the soap envelope
     * 
     * @param env soap envelope
     * @param wssConfig
     * @throws java.lang.Exception Thrown when there is a problem in verification
     */
    private List<WSSecurityEngineResult> verify(
        Document doc, WSSConfig wssConfig, RequestData data
    ) throws Exception {
        WSSecurityEngine secEngine = new WSSecurityEngine();
        secEngine.setWssConfig(wssConfig);
        Element elem = WSSecurityUtil.getSecurityHeader(doc, null);
        data.setSigCrypto(crypto);
        return secEngine.processSecurityHeader(elem, data);
    }
    
    
}
