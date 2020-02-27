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

package org.apache.ws.security.saml.ext;

import java.io.InputStream;
import java.security.KeyStore;

import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.common.SAML2CallbackHandler;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoType;
import org.apache.ws.security.components.crypto.Merlin;
import org.apache.ws.security.saml.SAMLKeyInfo;
import org.apache.ws.security.saml.ext.builder.SAML2Constants;
import org.apache.ws.security.util.DOM2Writer;
import org.apache.ws.security.util.Loader;
import org.junit.Assert;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * A list of test-cases to test the functionality of signing with
 * AssertionWrapper class implementation.
 */
public class AssertionSigningTest extends org.junit.Assert {

    private Crypto issuerCrypto = null;
    // Default Canonicalization algorithm used by AssertionWrapper class.
    private final String defaultCanonicalizationAlgorithm = SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS;
    // Default RSA Signature algorithm used by AssertionWrapper class.
    private final String defaultRSASignatureAlgorithm = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1;
    // Default DSA Signature algorithm used by AssertionWrapper class.
    private final String defaultDSASignatureAlgorithm = SignatureConstants.ALGO_ID_SIGNATURE_DSA;
    // Custom Signature algorithm
    private final String customSignatureAlgorithm = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256;
    // Custom Canonicalization algorithm
    private final String customCanonicalizationAlgorithm = SignatureConstants.ALGO_ID_C14N_OMIT_COMMENTS;
    // Custom Signature Digest algorithm
    private final String customSignatureDigestAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256";
    private final DocumentBuilderFactory dbf;

    public AssertionSigningTest() throws Exception {
        WSSConfig.init();
        // Load the issuer keystore
        issuerCrypto = new Merlin();
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        ClassLoader loader = Loader.getClassLoader(AssertionSigningTest.class);
        InputStream input = Merlin.loadInputStream(loader,
                "keys/client_keystore.jks");
        keyStore.load(input, "password".toCharArray());
        ((Merlin) issuerCrypto).setKeyStore(keyStore);
        
        dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
    }

    /**
     * Test that creates an AssertionWrapper object and signs using default
     * signature and canonicalization algorithms. The defaults should match
     * otherwise the test-case fails.
     */
    @org.junit.Test
    public void testSigningWithDefaultAlgorithms() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler
                .setConfirmationMethod(SAML2Constants.CONF_SENDER_VOUCHES);
        callbackHandler.setIssuer("www.example.com");
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);
        assertion.signAssertion("client_certchain", "password", issuerCrypto,
                false);
        Signature signature = assertion.getSaml2().getSignature();
        Assert.assertTrue(signature.getSignatureAlgorithm().equalsIgnoreCase(
                defaultRSASignatureAlgorithm)
                || signature.getSignatureAlgorithm().equalsIgnoreCase(
                        defaultDSASignatureAlgorithm));
        Assert.assertEquals(defaultCanonicalizationAlgorithm,
                signature.getCanonicalizationAlgorithm());
        
        // Verify Signature
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("client_certchain");
        SAMLKeyInfo keyInfo = new SAMLKeyInfo(issuerCrypto.getX509Certificates(cryptoType));
        
        Document doc = dbf.newDocumentBuilder().newDocument();
        
        Element assertionElement = assertion.toDOM(doc);
        doc.appendChild(assertionElement);
        
        assertion = new AssertionWrapper(assertionElement);
        assertion.verifySignature(keyInfo);
    }

    /**
     * Test that creates an AssertionWrapper object and signs using custom
     * signature and canonicalization algorithms.
     */
    @org.junit.Test
    public void testSigningWithCustomAlgorithms() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler
                .setConfirmationMethod(SAML2Constants.CONF_SENDER_VOUCHES);
        callbackHandler.setIssuer("www.example.com");
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);
        assertion.signAssertion("client_certchain", "password", issuerCrypto,
                false, customCanonicalizationAlgorithm,
                customSignatureAlgorithm, customSignatureDigestAlgorithm);
        Signature signature = assertion.getSaml2().getSignature();
        Assert.assertEquals(customSignatureAlgorithm,
                signature.getSignatureAlgorithm());
        Assert.assertEquals(customCanonicalizationAlgorithm,
                signature.getCanonicalizationAlgorithm());
        
        Document doc = dbf.newDocumentBuilder().newDocument();
        
        Element assertionElement = assertion.toDOM(doc);
        doc.appendChild(assertionElement);
        String assertionString = DOM2Writer.nodeToString(assertionElement);
        Assert.assertTrue(assertionString.contains(customSignatureDigestAlgorithm));

        // Verify Signature
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("client_certchain");
        SAMLKeyInfo keyInfo = new SAMLKeyInfo(issuerCrypto.getX509Certificates(cryptoType));
        
        assertion = new AssertionWrapper(assertionElement);
        assertion.verifySignature(keyInfo);
    }
    
}
