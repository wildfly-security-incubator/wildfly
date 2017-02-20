/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2012, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.jboss.as.test.integration.security.loginmodules;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Locale;

import org.apache.commons.io.FileUtils;
import org.apache.http.client.ClientProtocolException;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.OperateOnDeployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.as.arquillian.api.ServerSetup;
import org.jboss.as.arquillian.api.ServerSetupTask;
import org.jboss.as.arquillian.container.ManagementClient;
import org.jboss.as.test.categories.CommonCriteria;
import org.jboss.as.test.integration.ejb.security.EjbSecurityDomainSetup;
import org.jboss.as.test.integration.security.common.Coding;
import org.jboss.as.test.integration.security.common.Utils;
import org.jboss.as.test.integration.security.common.servlets.SimpleSecuredServlet;
import org.jboss.as.test.integration.security.common.servlets.SimpleServlet;
import org.jboss.logging.Logger;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;

/**
 * Tests for UserRoles login module.
 *
 * @author Jan Lanik
 * @author Josef Cacek
 * @author Jan Kalina
 */
@RunWith(Arquillian.class)
@ServerSetup({
        UsersRolesLoginModuleTestCase.PropertyFilesSetup.class,
        UsersRolesLoginModuleTestCase.ElytronDomain1Setup.class,
        UsersRolesLoginModuleTestCase.ElytronDomain2Setup.class
})
@RunAsClient
@Category(CommonCriteria.class)
public class UsersRolesLoginModuleTestCase {

    private static Logger LOGGER = Logger.getLogger(UsersRolesLoginModuleTestCase.class);

    private static final String DEP1 = "UsersRoles-externalFiles";
    private static final String DEP2 = "UsersRoles-externalFiles-MD5";

    private static final String REALM = "realm";
    private static final String ANIL = "anil";
    private static final String MARCUS = "marcus";
    private static final String ANIL_PWD = "anilPwd";
    private static final String MARCUS_PWD = "marcusPwd";

    private static final String USERS_EXT = "#$REALM_NAME=" + REALM + "$\n" + ANIL + "=" + ANIL_PWD + "\n" + MARCUS + "=" + MARCUS_PWD;
    private static final String ROLES_EXT = ANIL + "=" + SimpleSecuredServlet.ALLOWED_ROLE + "\n" + MARCUS + "=testRole";

    private static final String USERS_EXT_MD5 = "#$REALM_NAME=" + REALM + "$\n" + ANIL + "=" + Utils.hashMD5(ANIL + ":" + REALM + ":" + ANIL_PWD, Coding.HEX) + "\n" + MARCUS + "=" + Utils.hashMD5(MARCUS + ":" + REALM + ":" + MARCUS_PWD, Coding.HEX);
    private static final String ROLES_EXT_MD5 = ANIL + "=" + SimpleSecuredServlet.ALLOWED_ROLE + "\n" + MARCUS + "=testRole";

    /**
     * plaintext login with no additional options
     */
    @Deployment(name = DEP1)
    public static WebArchive appDeployment1() {
        return createWar(DEP1);
    }

    /**
     * passwords stored as MD5, no additional options
     */
    @Deployment(name = DEP2)
    public static WebArchive appDeployment2() {
        return createWar(DEP2);
    }

    /**
     * testExternalFiles
     *
     * @throws Exception
     * @see #USERS_EXT
     * @see #ROLES_EXT
     */
    @OperateOnDeployment(DEP1)
    @Test
    public void testExternalPlainFiles(@ArquillianResource URL url) throws Exception {
        testAccess(url, false);
    }

    /**
     * testMD5Password
     *
     * @throws Exception
     */
    @OperateOnDeployment(DEP2)
    @Test
    public void testExternalMD5Files(@ArquillianResource URL url) throws Exception {
        testAccess(url, false);
    }

    // Private methods -------------------------------------------------------

    /**
     * Tests access to a protected servlet.
     *
     * @param url
     * @param ignoreCase flag which says if the password should be case insensitive
     * @throws MalformedURLException
     * @throws ClientProtocolException
     * @throws IOException
     * @throws URISyntaxException
     */
    private void testAccess(URL url, boolean ignoreCase) throws IOException,
            URISyntaxException {
        final URL servletUrl = new URL(url.toExternalForm() + SimpleSecuredServlet.SERVLET_PATH.substring(1));
        //successful authentication and authorization
        assertEquals("Response body is not correct.", SimpleSecuredServlet.RESPONSE_BODY,
                Utils.makeCallWithBasicAuthn(servletUrl, ANIL, ANIL_PWD, 200));
        //successful authentication and unsuccessful authorization
        Utils.makeCallWithBasicAuthn(servletUrl, MARCUS, MARCUS_PWD, 403);
        //tests related to case (in)sensitiveness
        if (ignoreCase) {
            assertEquals("Response body is not correct.", SimpleSecuredServlet.RESPONSE_BODY,
                    Utils.makeCallWithBasicAuthn(servletUrl, ANIL, ANIL_PWD.toUpperCase(Locale.ENGLISH), 200));
            Utils.makeCallWithBasicAuthn(servletUrl, MARCUS, MARCUS_PWD.toLowerCase(Locale.ENGLISH), 403);
        } else {
            Utils.makeCallWithBasicAuthn(servletUrl, ANIL, ANIL_PWD.toUpperCase(Locale.ENGLISH), 401);
            Utils.makeCallWithBasicAuthn(servletUrl, MARCUS, MARCUS_PWD.toLowerCase(Locale.ENGLISH), 401);
        }
        //unsuccessful authentication
        Utils.makeCallWithBasicAuthn(servletUrl, ANIL, MARCUS_PWD, 401);
        Utils.makeCallWithBasicAuthn(servletUrl, ANIL, MARCUS, 401);
        Utils.makeCallWithBasicAuthn(servletUrl, ANIL_PWD, ANIL, 401);
        Utils.makeCallWithBasicAuthn(servletUrl, ANIL, Utils.hashMD5(ANIL, Coding.BASE_64), 401);
        Utils.makeCallWithBasicAuthn(servletUrl, ANIL, Utils.hashMD5(ANIL, Coding.HEX), 401);
    }

    /**
     * Creates {@link WebArchive} (WAR) for given deployment name.
     *
     * @param deployment
     * @return
     */
    private static WebArchive createWar(final String deployment) {
        LOGGER.trace("Starting deployment " + deployment);

        final WebArchive war = ShrinkWrap.create(WebArchive.class, deployment + ".war");
        war.addClasses(SimpleSecuredServlet.class, SimpleServlet.class);
        war.addAsWebInfResource(UsersRolesLoginModuleTestCase.class.getPackage(), "web-basic-authn.xml", "web.xml");
        war.addAsWebInfResource(new StringAsset("<jboss-web>" + //
                "<security-domain>" + deployment + "</security-domain>" + //
                "</jboss-web>"), "jboss-web.xml");

        return war;
    }

    // Embedded classes ------------------------------------------------------

    static class ElytronDomain1Setup extends EjbSecurityDomainSetup {

        @Override
        protected String getSecurityDomainName() {
            return DEP1;
        }

        @Override
        protected String getSecurityRealmName() {
            return DEP1;
        }

        @Override
        protected String getUndertowDomainName() {
            return DEP1;
        }

        @Override
        protected String getEjbDomainName() {
            return DEP1;
        }

        @Override
        protected String getSaslAuthenticationName() {
            return DEP1;
        }

        @Override
        protected String getRemotingConnectorName() {
            return DEP1;
        }

        @Override
        protected String getHttpAuthenticationName() {
            return DEP1;
        }

        @Override
        protected String getUsersFile() {
            return new File("test-users.properties").getAbsolutePath();
        }

        @Override
        protected String getGroupsFile() {
            return new File("test-roles.properties").getAbsolutePath();
        }

        @Override
        protected boolean isUsersFilePlain() {
            return true;
        }
    }

    static class ElytronDomain2Setup extends EjbSecurityDomainSetup {

        @Override
        protected String getSecurityDomainName() {
            return DEP2;
        }

        @Override
        protected String getSecurityRealmName() {
            return DEP2;
        }

        @Override
        protected String getUndertowDomainName() {
            return DEP2;
        }

        @Override
        protected String getEjbDomainName() {
            return DEP2;
        }

        @Override
        protected String getSaslAuthenticationName() {
            return DEP2;
        }

        @Override
        protected String getRemotingConnectorName() {
            return DEP2;
        }

        @Override
        protected String getHttpAuthenticationName() {
            return DEP2;
        }

        @Override
        protected String getUsersFile() {
            return new File("test-users-md5.properties").getAbsolutePath();
        }

        @Override
        protected String getGroupsFile() {
            return new File("test-roles-md5.properties").getAbsolutePath();
        }

        @Override
        protected boolean isUsersFilePlain() {
            return false;
        }
    }

    /**
     * A {@link ServerSetupTask} instance which creates property files with users and roles.
     *
     * @author Josef Cacek
     */
    static class PropertyFilesSetup implements ServerSetupTask {

        public static final File FILE_USERS = new File("test-users.properties");
        public static final File FILE_ROLES = new File("test-roles.properties");

        public static final File FILE_USERS_MD5 = new File("test-users-md5.properties");
        public static final File FILE_ROLES_MD5 = new File("test-roles-md5.properties");

        /**
         * Generates property files.
         */
        public void setup(ManagementClient managementClient, String containerId) throws Exception {
            FileUtils.writeStringToFile(FILE_USERS, USERS_EXT, "ISO-8859-1");
            FileUtils.writeStringToFile(FILE_ROLES, ROLES_EXT, "ISO-8859-1");
            FileUtils.writeStringToFile(FILE_USERS_MD5, USERS_EXT_MD5, "ISO-8859-1");
            FileUtils.writeStringToFile(FILE_ROLES_MD5, ROLES_EXT_MD5, "ISO-8859-1");
        }

        /**
         * Removes generated property files.
         */
        public void tearDown(ManagementClient managementClient, String containerId) throws Exception {
            FILE_USERS.delete();
            FILE_ROLES.delete();
            FILE_USERS_MD5.delete();
            FILE_ROLES_MD5.delete();
        }
    }

}
