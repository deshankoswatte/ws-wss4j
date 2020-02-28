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

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.wso2.carbon.identity.saml.common.util.SAMLInitializer;

import java.util.HashMap;
import java.util.Map;

import javax.xml.XMLConstants;

/**
 * This class intializes the Opensaml library. It is necessary to override DefaultBootstrap
 * to avoid instantiating Velocity, which we do not need in WSS4J.
 */
public class OpenSAMLBootstrap {
    
    /**
     * Initializes the OpenSAML library, loading default configurations.
     * 
     * @throws InitializationException thrown if there is a problem initializing the OpenSAML library
     */
    public static synchronized void bootstrap() throws InitializationException {

        SAMLInitializer.doBootstrap();
        initializeParserPool();
    }
    
    protected static void initializeParserPool() throws InitializationException {
        BasicParserPool pp = new BasicParserPool();
        pp.setMaxPoolSize(50);
        
        Map<String, Boolean> features = new HashMap<String, Boolean>();
        features.put(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        features.put("http://apache.org/xml/features/disallow-doctype-decl", true);
        pp.setBuilderFeatures(features);
        pp.setExpandEntityReferences(false);
        
        try {
            pp.initialize();
        } catch (ComponentInitializationException e) {
            throw new InitializationException("Error initializing parser pool", e);
        }
        XMLObjectProviderRegistrySupport.setParserPool(pp);
    }
}
