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
package org.apache.ws.security.message.token;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.Key;
import java.security.PrivilegedExceptionAction;

import javax.security.auth.kerberos.KerberosPrincipal;

import org.apache.ws.security.WSSecurityException;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;


public class KerberosServiceExceptionAction implements PrivilegedExceptionAction<KerberosServiceContext> {

    private static final String javaVersion = System.getProperty("java.version");
    private static final boolean isJava5Or6 = javaVersion.startsWith("1.5") || javaVersion.startsWith("1.6");
    private static final boolean isOracleJavaVendor = System.getProperty("java.vendor").startsWith("Oracle");
    private static final boolean isIBMJavaVendor = System.getProperty("java.vendor").startsWith("IBM");
    private static final boolean isHPJavaVendor = System.getProperty("java.vendor").startsWith("Hewlett-Packard");

    private static final String SUN_JGSS_INQUIRE_TYPE_CLASS = "com.sun.security.jgss.InquireType";
    private static final String SUN_JGSS_EXT_GSSCTX_CLASS = "com.sun.security.jgss.ExtendedGSSContext";

    private static final String IBM_JGSS_INQUIRE_TYPE_CLASS = "com.ibm.security.jgss.InquireType";
    private static final String IBM_JGSS_EXT_GSSCTX_CLASS = "com.ibm.security.jgss.ExtendedGSSContext";

    private static final String EXTENDED_JGSS_CONTEXT_INQUIRE_SEC_CONTEXT_METHOD_NAME = "inquireSecContext";
    private static final String EXTENDED_JGSS_CONTEXT_INQUIRE_TYPE_KRB5_GET_SESSION_KEY = "KRB5_GET_SESSION_KEY";

    private static final String JGSS_KERBEROS_TICKET_OID = "1.2.840.113554.1.2.2";
    private static final String JGSS_SPNEGO_TICKET_OID = "1.3.6.1.5.5.2";

    private static final String KERBEROS_TICKET_VALIDATION_ERROR_MSG_ID = "kerberosTicketValidationError";

    private byte[] ticket;
    private String serviceName;
    private boolean isUsernameServiceNameForm;
    private boolean spnego;

    public KerberosServiceExceptionAction(byte[] ticket, String serviceName, boolean isUsernameServiceNameForm,
                                          boolean spnego) {
        this.ticket = ticket;
        this.serviceName = serviceName;
        this.isUsernameServiceNameForm = isUsernameServiceNameForm;
        this.spnego = spnego;
    }


    /* (non-Javadoc)
     * @see java.security.PrivilegedExceptionAction#run()
     */
    public KerberosServiceContext run() throws GSSException, WSSecurityException {

        GSSManager gssManager = GSSManager.getInstance();

        GSSContext secContext = null;
        GSSName gssService = gssManager.createName(serviceName, isUsernameServiceNameForm 
                                                   ? GSSName.NT_USER_NAME : GSSName.NT_HOSTBASED_SERVICE);
        if (spnego) {
            Oid oid = new Oid(JGSS_SPNEGO_TICKET_OID);
            secContext = gssManager.createContext(gssService, oid, null, GSSContext.DEFAULT_LIFETIME);
        } else {
            Oid oid = new Oid(JGSS_KERBEROS_TICKET_OID);
            GSSCredential credentials = 
                gssManager.createCredential(
                    gssService, GSSCredential.DEFAULT_LIFETIME, oid, GSSCredential.ACCEPT_ONLY
                );
            secContext = gssManager.createContext(credentials);
        }

        KerberosServiceContext krbServiceCtx = null;

        try{
            byte[] returnedToken = secContext.acceptSecContext(ticket, 0, ticket.length);

            krbServiceCtx = new KerberosServiceContext();         
            
            if (secContext.getCredDelegState()) {
                krbServiceCtx.setDelegationCredential(secContext.getDelegCred());
            }
            
            GSSName clientName = secContext.getSrcName();
            krbServiceCtx.setPrincipal(new KerberosPrincipal(clientName.toString()));
            krbServiceCtx.setGssContext(secContext);
            krbServiceCtx.setKerberosToken(returnedToken);
            
            if (!isJava5Or6 && (isOracleJavaVendor || isIBMJavaVendor || isHPJavaVendor)) {
                try {
                    @SuppressWarnings("rawtypes")
                    Class inquireType = Class.forName(isIBMJavaVendor ? IBM_JGSS_INQUIRE_TYPE_CLASS : SUN_JGSS_INQUIRE_TYPE_CLASS);

                    @SuppressWarnings("rawtypes")
                    Class extendedGSSContext = Class.forName(isIBMJavaVendor ? IBM_JGSS_EXT_GSSCTX_CLASS : SUN_JGSS_EXT_GSSCTX_CLASS);

                    @SuppressWarnings("unchecked")
                    Method inquireSecContext = extendedGSSContext.getMethod(EXTENDED_JGSS_CONTEXT_INQUIRE_SEC_CONTEXT_METHOD_NAME, inquireType);

                    @SuppressWarnings("unchecked")
                    Key key = (Key) inquireSecContext.invoke(secContext, Enum.valueOf(inquireType, EXTENDED_JGSS_CONTEXT_INQUIRE_TYPE_KRB5_GET_SESSION_KEY));

                    krbServiceCtx.setSessionKey(key);
                }
                catch (ClassNotFoundException e) {
                    throw new WSSecurityException(
                        WSSecurityException.FAILURE, KERBEROS_TICKET_VALIDATION_ERROR_MSG_ID, new Object[] {}, e
                    );
                }
                catch (NoSuchMethodException e) {
                    throw new WSSecurityException(
                        WSSecurityException.FAILURE, KERBEROS_TICKET_VALIDATION_ERROR_MSG_ID, new Object[] {}, e
                    );
                }
                catch (InvocationTargetException e) {
                    throw new WSSecurityException(
                        WSSecurityException.FAILURE, KERBEROS_TICKET_VALIDATION_ERROR_MSG_ID, new Object[] {}, e.getCause()
                    );
                }
                catch (IllegalAccessException e) {
                    throw new WSSecurityException(
                        WSSecurityException.FAILURE, KERBEROS_TICKET_VALIDATION_ERROR_MSG_ID, new Object[] {}, e
                    );
                }      
            }            
        } finally {
            if (null != secContext && !spnego) {
                secContext.dispose();    
            }
        }               

        return krbServiceCtx;
    }

}
