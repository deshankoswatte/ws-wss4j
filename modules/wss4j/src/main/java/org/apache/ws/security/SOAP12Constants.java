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

package org.apache.ws.security;

import javax.xml.namespace.QName;

/**
 * SOAP 1.2 constants
 *
 * @author Glen Daniels (gdaniels@apache.org)
 * @author Andras Avar (andras.avar@nokia.com)
 */
public class SOAP12Constants implements SOAPConstants {
    /**
     * 
     */
    private static final long serialVersionUID = 3784866613259361834L;
    private static final QName headerQName = new QName(WSConstants.URI_SOAP12_ENV,
            WSConstants.ELEM_HEADER);
    private static final QName bodyQName = new QName(WSConstants.URI_SOAP12_ENV,
            WSConstants.ELEM_BODY);
    private static final QName roleQName = new QName(WSConstants.URI_SOAP12_ENV,
            WSConstants.ATTR_ROLE);
    
    // Public constants for SOAP 1.2
    
    /**
     * MessageContext property name for webmethod
     */
    public static final String PROP_WEBMETHOD = "soap12.webmethod";

    public String getEnvelopeURI() {
        return WSConstants.URI_SOAP12_ENV;
    }

    public QName getHeaderQName() {
        return headerQName;
    }

    public QName getBodyQName() {
        return bodyQName;
    }

    /**
     * Obtain the QName for the role attribute (actor/role)
     */
    public QName getRoleAttributeQName() {
        return roleQName;
    }

    /**
     * Obtain the "next" role/actor URI
     */
    public String getNextRoleURI() {
        return WSConstants.URI_SOAP12_NEXT_ROLE;
    }

    /**
     * Obtain the MustUnderstand string
     */
    public String getMustUnderstand() {
        return "true";
    }
    
}
