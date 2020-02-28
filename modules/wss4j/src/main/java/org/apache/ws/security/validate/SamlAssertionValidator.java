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

package org.apache.ws.security.validate;

import java.util.Date;
import java.util.List;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.cache.ReplayCache;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.saml.SAMLKeyInfo;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.apache.ws.security.saml.ext.OpenSAMLUtil;
import org.apache.ws.security.saml.ext.builder.SAML1Constants;
import org.apache.ws.security.saml.ext.builder.SAML2Constants;
import org.apache.ws.security.util.InetAddressUtils;
import org.joda.time.DateTime;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml1.core.AuthenticationStatement;
import org.opensaml.saml.saml2.core.AuthnStatement;

/**
 * This class validates a SAML Assertion, which is wrapped in an "AssertionWrapper" instance.
 * It assumes that the AssertionWrapper instance has already verified the signature on the
 * assertion (done by the SAMLTokenProcessor). It verifies trust in the signature, and also
 * checks that the Subject contains a KeyInfo (and processes it) for the holder-of-key case,
 * and verifies that the Assertion is signed as well for holder-of-key. 
 */
public class SamlAssertionValidator extends SignatureTrustValidator {
    
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(SamlAssertionValidator.class);
    
    /**
     * The time in seconds in the future within which the NotBefore time of an incoming 
     * Assertion is valid. The default is 60 seconds.
     */
    private int futureTTL = 60;
    
    /**
     * The time in seconds within which a SAML Assertion is valid, if it does not contain
     * a NotOnOrAfter Condition. The default is 30 minutes.
     */
    private int ttl = 60 * 30;
    
    /**
     * Whether to validate the signature of the Assertion (if it exists) against the 
     * relevant profile. Default is true.
     */
    private boolean validateSignatureAgainstProfile = true;
    
    /**
     * If this is set, then the value must appear as one of the Subject Confirmation Methods
     */
    private String requiredSubjectConfirmationMethod;
    
    /**
     * If this is set, at least one of the standard Subject Confirmation Methods *must*
     * be present in the assertion (Bearer / SenderVouches / HolderOfKey).
     */
    private boolean requireStandardSubjectConfirmationMethod = true;
    
    /**
     * If this is set, an Assertion with a Bearer SubjectConfirmation Method must be
     * signed 
     */
    private boolean requireBearerSignature = true;
    
    /**
     * Set the time in seconds in the future within which the NotBefore time of an incoming 
     * Assertion is valid. The default is 60 seconds.
     */
    public void setFutureTTL(int newFutureTTL) {
        futureTTL = newFutureTTL;
    }
    
    /**
     * Validate the credential argument. It must contain a non-null AssertionWrapper. 
     * A Crypto and a CallbackHandler implementation is also required to be set.
     * 
     * @param credential the Credential to be validated
     * @param data the RequestData associated with the request
     * @throws WSSecurityException on a failed validation
     */
    public Credential validate(Credential credential, RequestData data) throws WSSecurityException {
        if (credential == null || credential.getAssertion() == null) {
            throw new WSSecurityException(WSSecurityException.FAILURE, "noCredential");
        }
        AssertionWrapper assertion = credential.getAssertion();
        
        // Check the Subject Confirmation requirements
        verifySubjectConfirmationMethod(assertion);
        
        // Check conditions
        checkConditions(assertion);
        
        // Check the audience restrictions
        checkAudienceRestrictions(assertion, data.getAudienceRestrictions());
        
        // Check the AuthnStatements of the assertion (if any)
        checkAuthnStatements(assertion);
        
        // Check OneTimeUse Condition
        checkOneTimeUse(assertion, data);
        
        // Validate the assertion against schemas/profiles
        validateAssertion(assertion);

        // Verify trust on the signature
        if (assertion.isSigned()) {
            verifySignedAssertion(assertion, data);
        }
        return credential;
    }
    
    /**
     * Check the Subject Confirmation method requirements
     */
    protected void verifySubjectConfirmationMethod(
        AssertionWrapper samlAssertion
    ) throws WSSecurityException {
        
        List<String> methods = samlAssertion.getConfirmationMethods();
        if (methods == null || methods.isEmpty()) {
            if (requiredSubjectConfirmationMethod != null) {
                LOG.debug("A required subject confirmation method was not present");
                throw new WSSecurityException(WSSecurityException.FAILURE, 
                                          "invalidSAMLsecurity");
            } else if (requireStandardSubjectConfirmationMethod) {
                LOG.debug("A standard subject confirmation method was not present");
                throw new WSSecurityException(WSSecurityException.FAILURE, 
                                          "invalidSAMLsecurity");
            }
        }
        
        boolean signed = samlAssertion.isSigned();
        boolean requiredMethodFound = false;
        boolean standardMethodFound = false;
        for (String method : methods) {
            if (OpenSAMLUtil.isMethodHolderOfKey(method)) {
                if (samlAssertion.getSubjectKeyInfo() == null) {
                    LOG.debug("There is no Subject KeyInfo to match the holder-of-key subject conf method");
                    throw new WSSecurityException(WSSecurityException.FAILURE, "noKeyInSAMLToken");
                }
                
                // The assertion must have been signed for HOK
                if (!signed) {
                    LOG.debug("A holder-of-key assertion must be signed");
                    throw new WSSecurityException(WSSecurityException.FAILURE, "invalidSAMLsecurity");
                }
                standardMethodFound = true;
            }
            
            if (method != null) {
                if (method.equals(requiredSubjectConfirmationMethod)) {
                    requiredMethodFound = true;
                }
                if (SAML2Constants.CONF_BEARER.equals(method)
                    || SAML1Constants.CONF_BEARER.equals(method)) {
                    standardMethodFound = true;
                    if (requireBearerSignature && !signed) {
                        LOG.debug("A Bearer Assertion was not signed");
                        throw new WSSecurityException(WSSecurityException.FAILURE, 
                                                      "invalidSAMLsecurity");
                    }
                } else if (SAML2Constants.CONF_SENDER_VOUCHES.equals(method)
                    || SAML1Constants.CONF_SENDER_VOUCHES.equals(method)) {
                    standardMethodFound = true;
                }
            }
        }
        
        if (!requiredMethodFound && requiredSubjectConfirmationMethod != null) {
            LOG.debug("A required subject confirmation method was not present");
            throw new WSSecurityException(WSSecurityException.FAILURE, 
                                          "invalidSAMLsecurity");
        }
        
        if (!standardMethodFound && requireStandardSubjectConfirmationMethod) {
            LOG.debug("A standard subject confirmation method was not present");
            throw new WSSecurityException(WSSecurityException.FAILURE, 
                                      "invalidSAMLsecurity");
        }
    }
    
    /**
     * Verify trust in the signature of a signed Assertion. This method is separate so that
     * the user can override if if they want.
     * @param assertion The signed Assertion
     * @param data The RequestData context
     * @return A Credential instance
     * @throws WSSecurityException
     */
    protected Credential verifySignedAssertion(
        AssertionWrapper assertion,
        RequestData data
    ) throws WSSecurityException {
        Credential trustCredential = new Credential();
        SAMLKeyInfo samlKeyInfo = assertion.getSignatureKeyInfo();
        trustCredential.setPublicKey(samlKeyInfo.getPublicKey());
        trustCredential.setCertificates(samlKeyInfo.getCerts());
        return super.validate(trustCredential, data);
    }
    
    /**
     * Check the Conditions of the Assertion.
     */
    protected void checkConditions(AssertionWrapper assertion) throws WSSecurityException {
        DateTime validFrom = null;
        DateTime validTill = null;
        DateTime issueInstant = null;
        
        if (assertion.getSamlVersion().equals(SAMLVersion.VERSION_20)
            && assertion.getSaml2().getConditions() != null) {
            validFrom = assertion.getSaml2().getConditions().getNotBefore();
            validTill = assertion.getSaml2().getConditions().getNotOnOrAfter();
            issueInstant = assertion.getSaml2().getIssueInstant();
        } else if (assertion.getSamlVersion().equals(SAMLVersion.VERSION_11)
            && assertion.getSaml1().getConditions() != null) {
            validFrom = assertion.getSaml1().getConditions().getNotBefore();
            validTill = assertion.getSaml1().getConditions().getNotOnOrAfter();
            issueInstant = assertion.getSaml1().getIssueInstant();
        }
        
        if (validFrom != null) {
            DateTime currentTime = new DateTime();
            currentTime = currentTime.plusSeconds(futureTTL);
            if (validFrom.isAfter(currentTime)) {
                LOG.debug("SAML Token condition (Not Before) not met");
                throw new WSSecurityException(WSSecurityException.FAILURE, "invalidSAMLsecurity");
            }
        }

        if (validTill != null && validTill.isBeforeNow()) {
            LOG.debug("SAML Token condition (Not On Or After) not met");
            throw new WSSecurityException(WSSecurityException.FAILURE, "invalidSAMLsecurity");
        }
        
        // IssueInstant is not strictly in Conditions, but it has similar semantics to 
        // NotBefore, so including it here
        
        // Check the IssueInstant is not in the future, subject to the future TTL
        if (issueInstant != null) {
            DateTime currentTime = new DateTime();
            currentTime = currentTime.plusSeconds(futureTTL);
            if (issueInstant.isAfter(currentTime)) {
                LOG.debug("SAML Token IssueInstant not met");
                throw new WSSecurityException(WSSecurityException.FAILURE, "invalidSAMLsecurity");
            }
            
            // If there is no NotOnOrAfter, then impose a TTL on the IssueInstant.
            if (validTill == null) {
                currentTime = new DateTime();
                currentTime.minusSeconds(ttl);
                
                if (issueInstant.isBefore(currentTime)) {
                    LOG.debug("SAML Token IssueInstant not met. The assertion was created too long ago.");
                    throw new WSSecurityException(WSSecurityException.FAILURE, "invalidSAMLsecurity");
                }
            }
        }
    }
    
    /**
     * Check the AudienceRestrictions of the Assertion
     */
    public void checkAudienceRestrictions(
        AssertionWrapper assertion, List<String> audienceRestrictions
    ) throws WSSecurityException {
        // Now check the audience restriction conditions
        if (audienceRestrictions == null || audienceRestrictions.isEmpty()) {
            return;
        }
        
        if (assertion.getSamlVersion().equals(SAMLVersion.VERSION_20) 
            && assertion.getSaml2().getConditions() != null) {
            org.opensaml.saml.saml2.core.Conditions conditions =
                assertion.getSaml2().getConditions();
            if (conditions != null && conditions.getAudienceRestrictions() != null
                && !conditions.getAudienceRestrictions().isEmpty()) {
                boolean foundAddress = false;
                for (org.opensaml.saml.saml2.core.AudienceRestriction audienceRestriction
                    : conditions.getAudienceRestrictions()) {
                    if (audienceRestriction.getAudiences() != null) {
                        List<org.opensaml.saml.saml2.core.Audience> audiences =
                            audienceRestriction.getAudiences();
                        for (org.opensaml.saml.saml2.core.Audience audience : audiences) {
                            String audienceURI = audience.getAudienceURI();
                            if (audienceRestrictions.contains(audienceURI)) {
                                foundAddress = true;
                                break;
                            }
                        }
                    }
                }
                
                if (!foundAddress) {
                    throw new WSSecurityException(WSSecurityException.FAILURE, "invalidSAMLsecurity");
                }
            }
        } else if (assertion.getSamlVersion().equals(SAMLVersion.VERSION_11) 
            && assertion.getSaml1().getConditions() != null) {
            org.opensaml.saml.saml1.core.Conditions conditions =
                assertion.getSaml1().getConditions();
            if (conditions != null && conditions.getAudienceRestrictionConditions() != null
                && !conditions.getAudienceRestrictionConditions().isEmpty()) {
                boolean foundAddress = false;
                for (org.opensaml.saml.saml1.core.AudienceRestrictionCondition audienceRestriction
                    : conditions.getAudienceRestrictionConditions()) {
                    if (audienceRestriction.getAudiences() != null) {
                        List<org.opensaml.saml.saml1.core.Audience> audiences =
                            audienceRestriction.getAudiences();
                        for (org.opensaml.saml.saml1.core.Audience audience : audiences) {
                            String audienceURI = audience.getUri();
                            if (audienceRestrictions.contains(audienceURI)) {
                                foundAddress = true;
                                break;
                            }
                        }
                    }
                }
                
                if (!foundAddress) {
                    throw new WSSecurityException(WSSecurityException.FAILURE, "invalidSAMLsecurity");
                }
            }
        }
    }

    /**
     * Check the AuthnStatements of the Assertion (if any)
     */
    protected void checkAuthnStatements(AssertionWrapper assertion) throws WSSecurityException {
        if (assertion.getSamlVersion().equals(SAMLVersion.VERSION_20)
            && assertion.getSaml2().getAuthnStatements() != null) {
            List<AuthnStatement> authnStatements = assertion.getSaml2().getAuthnStatements();

            for (AuthnStatement authnStatement : authnStatements) {
                DateTime authnInstant = authnStatement.getAuthnInstant();
                DateTime sessionNotOnOrAfter = authnStatement.getSessionNotOnOrAfter();
                String subjectLocalityAddress = null;

                if (authnStatement.getSubjectLocality() != null
                    && authnStatement.getSubjectLocality().getAddress() != null) {
                    subjectLocalityAddress = authnStatement.getSubjectLocality().getAddress();
                }

                validateAuthnStatement(authnInstant, sessionNotOnOrAfter, 
                                       subjectLocalityAddress, futureTTL);
            }
        } else if (assertion.getSamlVersion().equals(SAMLVersion.VERSION_11)
            && assertion.getSaml1().getAuthenticationStatements() != null) {
            List<AuthenticationStatement> authnStatements = 
                assertion.getSaml1().getAuthenticationStatements();

            for (AuthenticationStatement authnStatement : authnStatements) {
                DateTime authnInstant = authnStatement.getAuthenticationInstant();
                String subjectLocalityAddress = null;

                if (authnStatement.getSubjectLocality() != null
                    && authnStatement.getSubjectLocality().getIPAddress() != null) {
                    subjectLocalityAddress = authnStatement.getSubjectLocality().getIPAddress();
                }

                validateAuthnStatement(authnInstant, null, 
                                       subjectLocalityAddress, futureTTL);
            }
        }
    }
        
    private void validateAuthnStatement(
        DateTime authnInstant, DateTime sessionNotOnOrAfter, String subjectLocalityAddress,
        int futureTTL
    ) throws WSSecurityException {
        // AuthnInstant in the future
        DateTime currentTime = new DateTime();
        currentTime = currentTime.plusSeconds(futureTTL);
        if (authnInstant.isAfter(currentTime)) {
            LOG.debug("SAML Token AuthnInstant not met");
            throw new WSSecurityException(WSSecurityException.FAILURE, "invalidSAMLsecurity");
        }

        // Stale SessionNotOnOrAfter
        if (sessionNotOnOrAfter != null && sessionNotOnOrAfter.isBeforeNow()) {
            LOG.debug("SAML Token SessionNotOnOrAfter not met");
            throw new WSSecurityException(WSSecurityException.FAILURE, "invalidSAMLsecurity");
        }

        // Check that the SubjectLocality address is an IP address
        if (subjectLocalityAddress != null
            && !(InetAddressUtils.isIPv4Address(subjectLocalityAddress)
                || InetAddressUtils.isIPv6Address(subjectLocalityAddress))) {
            LOG.debug("SAML Token SubjectLocality address is not valid: " + subjectLocalityAddress);
            throw new WSSecurityException(WSSecurityException.FAILURE, "invalidSAMLsecurity");
        }
    }
    
    /**
     * Check the "OneTimeUse" Condition of the Assertion. If this is set then the Assertion
     * is cached (if a cache is defined), and must not have been previously cached
     */
    protected void checkOneTimeUse(
        AssertionWrapper samlAssertion, RequestData data
    ) throws WSSecurityException {
        if (samlAssertion.getSamlVersion().equals(SAMLVersion.VERSION_20)
            && samlAssertion.getSaml2().getConditions() != null
            && samlAssertion.getSaml2().getConditions().getOneTimeUse() != null 
            && data.getSamlOneTimeUseReplayCache() != null) {
            String identifier = samlAssertion.getId();

            ReplayCache replayCache = data.getSamlOneTimeUseReplayCache();
            if (replayCache.contains(identifier)) {
                throw new WSSecurityException(
                    WSSecurityException.INVALID_SECURITY,
                    "badSamlToken",
                    new Object[] {"A replay attack has been detected"});
            }

            DateTime expires = samlAssertion.getSaml2().getConditions().getNotOnOrAfter();
            if (expires != null) {
                Date rightNow = new Date();
                long currentTime = rightNow.getTime();
                long expiresTime = expires.getMillis();
                replayCache.add(identifier, 1L + (expiresTime - currentTime) / 1000L);
            } else {
                replayCache.add(identifier);
            }

            replayCache.add(identifier);
        }
    }

    /**
     * Validate the assertion against schemas/profiles
     */
    protected void validateAssertion(AssertionWrapper assertion) throws WSSecurityException {
        if (validateSignatureAgainstProfile) {
            assertion.validateSignatureAgainstProfile();
        }
        
//        if (assertion.getSaml1() != null) {
//            ValidatorSuite schemaValidators =
//                org.opensaml.Configuration.getValidatorSuite("saml1-schema-validator");
//            ValidatorSuite specValidators =
//                org.opensaml.Configuration.getValidatorSuite("saml1-spec-validator");
//            try {
//                schemaValidators.validate(assertion.getSaml1());
//                specValidators.validate(assertion.getSaml1());
//            } catch (ValidationException e) {
//                LOG.debug("Saml Validation error: " + e.getMessage(), e);
//                throw new WSSecurityException(
//                    WSSecurityException.FAILURE, "invalidSAMLsecurity", null, e
//                );
//            }
//        } else if (assertion.getSaml2() != null) {
//            ValidatorSuite schemaValidators =
//                org.opensaml.Configuration.getValidatorSuite("saml2-core-schema-validator");
//            ValidatorSuite specValidators =
//                org.opensaml.Configuration.getValidatorSuite("saml2-core-spec-validator");
//            try {
//                schemaValidators.validate(assertion.getSaml2());
//                specValidators.validate(assertion.getSaml2());
//            } catch (ValidationException e) {
//                LOG.debug("Saml Validation error: " + e.getMessage(), e);
//                throw new WSSecurityException(
//                    WSSecurityException.FAILURE, "invalidSAMLsecurity", null, e
//                );
//            }
//        }
    }

    /**
     * Whether to validate the signature of the Assertion (if it exists) against the 
     * relevant profile. Default is true.
     */
    public boolean isValidateSignatureAgainstProfile() {
        return validateSignatureAgainstProfile;
    }

    /**
     * Whether to validate the signature of the Assertion (if it exists) against the 
     * relevant profile. Default is true.
     */
    public void setValidateSignatureAgainstProfile(boolean validateSignatureAgainstProfile) {
        this.validateSignatureAgainstProfile = validateSignatureAgainstProfile;
    }

    public String getRequiredSubjectConfirmationMethod() {
        return requiredSubjectConfirmationMethod;
    }

    public void setRequiredSubjectConfirmationMethod(String requiredSubjectConfirmationMethod) {
        this.requiredSubjectConfirmationMethod = requiredSubjectConfirmationMethod;
    }

    public boolean isRequireStandardSubjectConfirmationMethod() {
        return requireStandardSubjectConfirmationMethod;
    }

    public void setRequireStandardSubjectConfirmationMethod(boolean requireStandardSubjectConfirmationMethod) {
        this.requireStandardSubjectConfirmationMethod = requireStandardSubjectConfirmationMethod;
    }

    public boolean isRequireBearerSignature() {
        return requireBearerSignature;
    }

    public void setRequireBearerSignature(boolean requireBearerSignature) {
        this.requireBearerSignature = requireBearerSignature;
    }
    
    public int getTtl() {
        return ttl;
    }

    public void setTtl(int ttl) {
        this.ttl = ttl;
    }

}
