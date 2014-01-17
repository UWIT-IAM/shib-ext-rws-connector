/* ========================================================================
 * Copyright (c) 2010-2012 The University of Washington
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ========================================================================
 */

package edu.washington.shibboleth.attribute.resolver.provider.dataConnector;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Vector;
import java.util.StringTokenizer;
import java.lang.IllegalArgumentException;


import java.net.URL;
import java.net.MalformedURLException;
import javax.xml.parsers.ParserConfigurationException;

import javax.naming.NamingException;
import javax.naming.directory.SearchResult;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import javax.xml.transform.dom.DOMSource;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.protocol.ClientContext;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager;
import org.apache.http.params.HttpConnectionParams;
import org.apache.http.params.HttpParams;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.AuthState;

import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.util.DatatypeHelper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;

import edu.internet2.middleware.shibboleth.common.attribute.BaseAttribute;
import edu.internet2.middleware.shibboleth.common.attribute.provider.BasicAttribute;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.AttributeResolutionException;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.provider.ShibbolethResolutionContext;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.provider.dataConnector.BaseDataConnector;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.provider.dataConnector.TemplateEngine;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.provider.dataConnector.TemplateEngine.CharacterEscapingStrategy;


import edu.internet2.middleware.shibboleth.common.session.LogoutEvent;

/**
 * <code>RwsDataConnector</code> provides a plugin to retrieve attributes from a restful webservice.
 */
public class RwsDataConnector extends BaseDataConnector implements ApplicationListener {

    /** Authentication type values. */
    public static enum AUTHENTICATION_TYPE {
        /** No authentication type. */
        NONE,
        /** Basic authentication type. */
        BASIC,
        /** Client cretificate authentication type. */
        CLIENT_CERT
    };

    /** Class logger. */
    private static Logger log = LoggerFactory.getLogger(RwsDataConnector.class);

    /** SSL trust managers. */
    private TrustManager[] sslTrustManagers;

    /** SSL key managers. */
    private KeyManager[] sslKeyManagers;

    /** Authentication type */
    private AUTHENTICATION_TYPE authenticationType;

    /** Username if basic auth */
    private String username;

    /** Password if basic auth */
    private String password;

    /** Cred provider if basic auth */
    private CredentialsProvider credsProvider;

    /** Whether an empty result set is an error. */
    private boolean noResultsIsError;

    /** Whether to cache search results for the duration of the session. */
    private boolean cacheResults;

    /** Time, in milliseconds, to wait for a search to return. */
    private int searchTimeLimit;

    private boolean mergeMultipleResults;

    /** Template engine used to change filter template into actual filter. */
    private TemplateEngine queryCreator;

    /** Template name that produces the query to use. */
    private String queryTemplateName;

    /** Template that produces the query to use. */
    private String queryTemplate;

    /** Base url of the webservice */
    private String baseUrl;
    private URL baseURL;
    private int basePort;

    /** Connection scheme registry */
    private SchemeRegistry schemeRegistry;

    /** Connection scheme */
    private Scheme scheme;

    /** Connection manager */
    private ThreadSafeClientConnManager connectionManager;

    /** max connections */
    private int maxConnections;

    /** Data cache. */
    private Map<String, Map<String, Map<String, BaseAttribute>>> cache;

    /** Whether this data connector has been initialized. */
    private boolean initialized;

    /** Filter value escaping strategy. */
    private final URLValueEscapingStrategy escapingStrategy = null;

    /** max results. */
    private int maxResults;

    /** parser for ws response. */
    private DocumentBuilder documentBuilder;

    /** xpath evaluator */
    XPathExpression xpathExpression;

    /** Attributes to fetch */
    private List<RwsAttribute> rwsAttributes;

    /** EntityIds of configured activating RPs */
    private List<String> configuredActivators;

    /** Filename of activating RP list */
    private String activatorsFilename;
    private long activatorsModified = 0;
    private long activatorsChecked = 0;
    private List<String> activators;

    /** interval in millisec to check the file */
    private long pollingFrequency;

    /**
     * This creates a new data connector with the supplied properties.
     * 
     * @param baseUrl <code>String</code> base url of the webservice
     * @param attributeXPath <code>String</code> xpath of attribute name response
     * @param maxConnection <code>int</code> maximum connections
     */
    public RwsDataConnector(String baseUrl, int maxConnections) {
        super();

        this.baseUrl = baseUrl;
        try {
           baseURL = new URL(baseUrl);
           basePort = baseURL.getPort();
           if (basePort<0) {
              basePort = baseURL.getDefaultPort();
              log.info("ws port not specified, using {}.", basePort);
           }
        } catch (MalformedURLException e) {
           log.error("RwsDataConnector: bad url: " + e);
        }

        this.maxConnections = maxConnections;
    }

    /**
     * Initializes the connector and prepares it for use.
     */
    public void initialize() {

        initialized = true;

        initializeConnectionManager();

        try {
           DocumentBuilderFactory domFactory = DocumentBuilderFactory.newInstance();
           domFactory.setNamespaceAware(true);
           domFactory.setValidating(false);
           String feature = "http://apache.org/xml/features/nonvalidating/load-external-dtd";
           domFactory.setFeature(feature, false);
           documentBuilder = domFactory.newDocumentBuilder();

         } catch (ParserConfigurationException e) {
           log.error("javax.xml.parsers.ParserConfigurationException: " + e);
         }

         for (int i=0; i<rwsAttributes.size(); i++) {
             RwsAttribute attr = rwsAttributes.get(i);
             try {
                XPath xpath = XPathFactory.newInstance().newXPath();
                log.debug("xpath for {} is {}", attr.name, attr.xPath);
                attr.xpathExpression = xpath.compile(attr.xPath);
             } catch (XPathExpressionException e) {
                log.error("xpath expr: " + e);
             } 
         }

         activators = new Vector<String>(configuredActivators);
         refreshActivators();

         registerTemplate();
         initializeCache();

    }

    /**
     * Initializes the http connection manager.
     */
    public void initializeConnectionManager() {

        if (initialized) {
           schemeRegistry = new SchemeRegistry();
           try {
               SSLContext ctx = SSLContext.getInstance("TLS");
               ctx.init(sslKeyManagers, sslTrustManagers, null);
               SSLSocketFactory sf = new SSLSocketFactory(ctx);
               scheme = new Scheme(baseURL.getProtocol(), basePort, sf);
               schemeRegistry.register(scheme);
           } catch (GeneralSecurityException e) {
               log.error("Error initializing CM: ", e);
           } catch (Exception e) {
               log.error("Error initializing CM: ", e);
           }
           connectionManager = new ThreadSafeClientConnManager(new BasicHttpParams(),schemeRegistry);
           // connectionManager.setMaxTotalConnections(maxConnections);
  
           if (authenticationType==AUTHENTICATION_TYPE.BASIC) {
               if (username==null || password==null) {
                   log.error("rws basic auth requires user and password");
               }
           }
           if (authenticationType==AUTHENTICATION_TYPE.CLIENT_CERT) {
               if (sslKeyManagers==null) {
                   log.error("rws client cert auth requires client cert");
               }
           }
        }
    }

    /**
     * Initializes the cache and prepares it for use. {@link #initialize()} must be called first or this method does
     * nothing.
     */
    protected void initializeCache() {
        if (cacheResults && initialized) {
            cache = new HashMap<String, Map<String, Map<String, BaseAttribute>>>();
        }
    }

    /**
     * This removes all entries from the cache. {@link #initialize()} must be called first or this method does nothing.
     */
    protected void clearCache() {
        if (cacheResults && initialized) {
            cache.clear();
        }
    }

    /**
     * Registers the query template with template engine. {@link #initialize()} must be called first or this method does
     * nothing.
     */
    protected void registerTemplate() {
        if (initialized) {
            queryTemplateName = "shibboleth.resolver.gws." + getId();
            queryCreator.registerTemplate(queryTemplateName, queryTemplate);
        }
    }

    /** {@inheritDoc} */
    public void onApplicationEvent(ApplicationEvent evt) {
        if (evt instanceof LogoutEvent) {
            LogoutEvent logoutEvent = (LogoutEvent) evt;
            cache.remove(logoutEvent.getUserSession().getPrincipalName());
        }
    }

    /** {@inheritDoc} */
    public Map<String, BaseAttribute> resolve(ShibbolethResolutionContext resolutionContext)
            throws AttributeResolutionException {
        String queryString = queryCreator.createStatement(queryTemplateName, resolutionContext, getDependencyIds(),
                escapingStrategy);
        queryString = queryString.trim();
        log.debug("RWS query filter: {}", queryString);

        synchronized (this) {
           refreshActivators();
           boolean isActive = true;   // no activators means always active
           if (activators!=null && activators.size()>0) {
              isActive = false;
              String rpId = resolutionContext.getAttributeRequestContext().getPeerEntityId();
              log.debug("checking {} for activating RP", rpId );
              for (int i=0; i<activators.size(); i++) {
                 if (activators.get(i).equals(rpId)) {
                     isActive = true;
                     break;
                 }
              }
           }
           if (!isActive) {
               log.debug("not active.  returning no attributes");
               return new HashMap<String, BaseAttribute>();
           }
        }

        // create Attribute objects to return
        Map<String, BaseAttribute> attributes = null;

        // check for cached data
        if (cacheResults) {
            log.debug("Rws checking cache for search results");
            attributes = getCachedAttributes(resolutionContext, queryString);
            if (attributes != null && log.isDebugEnabled()) {
                log.debug("Rws returning attributes from cache");
            }
        }

        // results not found in the cache
        if (attributes == null) {
            log.debug("Retrieving attributes from GWS");
            attributes = getRwsAttributes(queryString);
            if (cacheResults && attributes != null) {
                setCachedAttributes(resolutionContext, queryString, attributes);
                log.debug("Stored results in the cache");
            }
        }

        return attributes;
    }

    /** {@inheritDoc} */
    public void validate() throws AttributeResolutionException {
        if (false) throw new AttributeResolutionException("rws");
    }

    /**
     * This queries the WS.
     * 
     * @param queryString <code>String</code> the queryString that produced the attributes
     * @return <code>List</code> of results
     * @throws AttributeResolutionException if an error occurs performing the search
     */
    protected Map<String, BaseAttribute> getRwsAttributes(String queryString) throws AttributeResolutionException {
      try {
        HttpParams httpParams = new BasicHttpParams();
        HttpConnectionParams.setConnectionTimeout(httpParams, searchTimeLimit);
        HttpConnectionParams.setSoTimeout(httpParams, searchTimeLimit);
        DefaultHttpClient httpClient = new DefaultHttpClient((ClientConnectionManager)connectionManager, httpParams);
        if (authenticationType==AUTHENTICATION_TYPE.BASIC) {
            httpClient.getCredentialsProvider().setCredentials(
                      new AuthScope(baseURL.getHost(), basePort), 
                      new UsernamePasswordCredentials(username, password));
        }
        HttpGet httpget = new HttpGet(baseUrl + queryString);
        HttpResponse response = httpClient.execute(httpget);
        HttpEntity entity = response.getEntity();

        // null is error - should get something
        if (entity == null) {
           throw new AttributeResolutionException("httpclient get exception");
        }
        
        // parse and return the response
        Document doc = documentBuilder.parse(entity.getContent());

        Map<String, BaseAttribute> attributes = new HashMap<String, BaseAttribute>();

        for (int i=0; i<rwsAttributes.size(); i++) {
           RwsAttribute attr = rwsAttributes.get(i);

           Object result = attr.xpathExpression.evaluate(doc, XPathConstants.NODESET);
           NodeList nodes = (NodeList) result;
           log.debug("got {} matches to the xpath for {}", nodes.getLength(), attr.name);

           List<String> results = new Vector<String>();
           if (nodes.getLength()==0 && attr.noResultIsError) {
              log.error("got no attributes for {}, which required attriubtes", attr.name);
              throw new AttributeResolutionException("no attributes for " + attr.name);
           }
           for (int j = 0; j < nodes.getLength(); j++) {
              if (maxResults>0 && maxResults<j) {
                  log.error("too many results for {}", attr.name);
                  break;
              }
              results.add((String)nodes.item(j).getTextContent());
           }
           addBaseAttributes(attributes, attr.name, results);
        }
        return attributes;

      } catch (IOException e) {
          log.error("get rws io excpet: " + e);
          throw new AttributeResolutionException();
      } catch (SAXException e) {
          log.error("get rws sax excpet: " + e);
          throw new AttributeResolutionException();
      } catch (IllegalArgumentException e) {
          log.error("get rws arg excpet: " + e);
          throw new AttributeResolutionException();
      } catch (XPathExpressionException e) {
          log.error("get rws arg excpet: " + e);
          throw new AttributeResolutionException();
      } 

    }

    /**
     * This returns a map of attribute ids to attributes from the supplied search results.
     * 
     * @param results <code>Iterator</code> of search results
     * @return <code>Map</code> of attribute ids to attributes
     * @throws AttributeResolutionException if an error occurs parsing attribute results
     */
    protected void addBaseAttributes(Map<String, BaseAttribute> attributes, String name, List<String> results) {

        if (results.size()>0) {

        BaseAttribute<String> attribute = new BasicAttribute<String>();
        ((BasicAttribute)attribute).setId(name);
            
        for(String result : results){
            if(!DatatypeHelper.isEmpty(result)){
               attribute.getValues().add(DatatypeHelper.safeTrimOrNullString(result));
            }
        }
        attributes.put(name, attribute);
        }
    }

    /**
     * This stores the supplied attributes in the cache.
     * 
     * @param resolutionContext <code>ResolutionContext</code>
     * @param searchFiler the queryString that produced the attributes
     * @param attributes <code>Map</code> of attribute ids to attributes
     */
    protected void setCachedAttributes(ShibbolethResolutionContext resolutionContext, String searchFiler,
            Map<String, BaseAttribute> attributes) {
        Map<String, Map<String, BaseAttribute>> results = null;
        String principal = resolutionContext.getAttributeRequestContext().getPrincipalName();
        if (cache.containsKey(principal)) {
            results = cache.get(principal);
        } else {
            results = new HashMap<String, Map<String, BaseAttribute>>();
            cache.put(principal, results);
        }
        results.put(searchFiler, attributes);
    }

    /**
     * This retrieves any cached attributes for the supplied resolution context. Returns null if nothing is cached.
     * 
     * @param resolutionContext <code>ResolutionContext</code>
     * @param queryString the search filter the produced the attributes
     * 
     * @return <code>Map</code> of attributes ids to attributes
     */
    protected Map<String, BaseAttribute> getCachedAttributes(ShibbolethResolutionContext resolutionContext,
            String queryString) {
        Map<String, BaseAttribute> attributes = null;
        if (cacheResults) {
            String principal = resolutionContext.getAttributeRequestContext().getPrincipalName();
            if (cache.containsKey(principal)) {
                Map<String, Map<String, BaseAttribute>> results = cache.get(principal);
                attributes = results.get(queryString);
            }
        }
        return attributes;
    }

    /**
     * Escapes values that will be included within a URL filter.
     */
    protected class URLValueEscapingStrategy implements CharacterEscapingStrategy {

        /** {@inheritDoc} */
        public String escape(String value) {
            return value.replace("*", "\\*").replace("(", "\\(").replace(")", "\\)").replace("\\", "\\");
        }
    }


    /** Bean property getters and setters */

    /**
     * This returns whether this connector will cache search results. The default is false.
     * 
     * @return <code>boolean</code>
     */
    public boolean isCacheResults() {
        return cacheResults;
    }

    /**
     * This sets whether this connector will cache search results.
     * 
     * @see #initializeCache()
     * 
     * @param b <code>boolean</code>
     */
    public void setCacheResults(boolean b) {
        cacheResults = b;
        if (!cacheResults) {
            cache = null;
        } else {
            initializeCache();
        }
    }

    /**
     * This returns whether this connector will throw an exception if no search results are found. The default is false.
     * 
     * @return <code>boolean</code>
     */
    public boolean isNoResultsIsError() {
        return noResultsIsError;
    }

    /**
     * This sets whether this connector will throw an exception if no search results are found.
     * 
     * @param b <code>boolean</code>
     */
    public void setNoResultsIsError(boolean b) {
        noResultsIsError = b;
    }

    /**
     * Gets the engine used to evaluate the query template.
     *
     * @return engine used to evaluate the query template
     */
    public TemplateEngine getTemplateEngine() {
        return queryCreator;
    }
    
    /**
     * Sets the engine used to evaluate the query template.
     *
     * @param engine engine used to evaluate the query template
     */
    public void setTemplateEngine(TemplateEngine engine) {
        queryCreator = engine;
        registerTemplate();
        clearCache();
    }

    /**
     * This returns the base URL this connector is using.
     *
     * @return <code>String</code>
     */
    public String getBaseUrl() {
        return baseUrl;
    }


    /**
     * Gets the query string 
     * 
     * @return query string 
     */
    public String getQueryTemplate() {
        return queryTemplate;
    }

    /**
     * Sets the authentication type
     * 
     * @param type typr 
     */
    public void setAuthenticationType(AUTHENTICATION_TYPE type) {
        authenticationType = type;
    }

    /**
     * This returns whether this connector will merge multiple search results into one result. The default is false.
     *
     * @return <code>boolean</code>
     */
    public boolean isMergeResults() {
        return mergeMultipleResults;
    }

    /**
     * This sets whether this connector will merge multiple search results into one result. This method will remove any
     * cached results.
     *
     * @see #clearCache()
     *
     * @param b <code>boolean</code>
     */
    public void setMergeResults(boolean b) {
        mergeMultipleResults = b;
        clearCache();
    }

    /**
     * Sets the template used to create queries.
     *
     * @param template template used to create queries
     */
    public void setQueryTemplate(String template) {
        queryTemplate = template;
        clearCache();
    }

    /**
     * This returns the SSL Socket Factory that will be used for all TLS and SSL connections 
     * 
     * @return <code>SSLSocketFactory</code>
     */
/**
    public SSLSocketFactory getSslSocketFactory() {
        return (SSLSocketFactory) scheme.getSocketFactory();
    }
 **/

    /**
     * This sets the SSL Socket Factory that will be used for all TLS and SSL connections.
     * 
     * @see #clearCache()
     * 
     * @param sf <code>SSLSocketFactory</code>
     */
/**
    public void setSslSocketFactory(SSLSocketFactory sf) {
        // scheme.setSocketFactory(sf);
        // clearCache();
        // initializeHttpPool();
    }
 **/

    /**
     * This returns the trust managers that will be used for all TLS and SSL connections to the ldap.
     * 
     * @return <code>TrustManager[]</code>
     */
    public TrustManager[] getSslTrustManagers() {
        return sslTrustManagers;
    }

    /**
     * This sets the trust managers that will be used for all TLS and SSL connections to the ldap. This method will
     * remove any cached results and initialize the connection manager.
     * 
     * @see #clearCache()
     * @see #setSslSocketFactory(SSLSocketFactory)
     * 
     * @param tc <code>X509Credential</code> to create TrustManagers with
     */
    public void setSslTrustManagers(X509Credential tc) {
        if (tc != null) {
            try {
                TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
                keystore.load(null, null);
                for (X509Certificate c : tc.getEntityCertificateChain()) {
                    keystore.setCertificateEntry("ldap_tls_trust_" + c.getSerialNumber(), c);
                }
                tmf.init(keystore);
                sslTrustManagers = tmf.getTrustManagers();
            } catch (GeneralSecurityException e) {
                log.error("Error initializing trust managers", e);
            } catch (IOException e) {
                log.error("Error initializing trust managers", e);
            }
        }
    }

    /**
     * This returns the key managers that will be used for all TLS and SSL connections to the ldap.
     * 
     * @return <code>KeyManager[]</code>
     */
    public KeyManager[] getSslKeyManagers() {
        return sslKeyManagers;
    }

    /**
     * This sets the key managers that will be used for all TLS and SSL connections to the ldap. 
     * 
     * @see #clearCache()
     * @see #initializeHttpPool()
     * @see #setSslSocketFactory(SSLSocketFactory)
     * 
     * @param kc <code>X509Credential</code> to create KeyManagers with
     */
    public void setSslKeyManagers(X509Credential kc) {
        if (kc != null) {
            try {
                KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
                keystore.load(null, null);
                keystore.setKeyEntry("ldap_tls_client_auth", kc.getPrivateKey(), "changeit".toCharArray(), kc
                        .getEntityCertificateChain().toArray(new X509Certificate[0]));
                kmf.init(keystore, "changeit".toCharArray());
                sslKeyManagers = kmf.getKeyManagers();
            } catch (GeneralSecurityException e) {
                log.error("Error initializing key managers", e);
            } catch (IOException e) {
                log.error("Error initializing key managers", e);
            }
        }
    }

    /**
     * This returns the hostname verifier that will be used for all TLS and SSL connections to the ldap.
     * 
     * @return <code>HostnameVerifier</code>
     */
/***
    public HostnameVerifier getHostnameVerifier() {
        return ldapConfig.getHostnameVerifier();
    }
 ***/

    /**
     * This sets the hostname verifier that will be used for all TLS and SSL connections. This method will
     * remove any cached results and initialize the connection manager.
     * 
     * @see #clearCache()
     * @see #initializeLdapPool()
     * 
     * @param hv <code>HostnameVerifier</code>
     */
/***
    public void setHostnameVerifier(HostnameVerifier hv) {
        ldapConfig.setHostnameVerifier(hv);
        clearCache();
        initializeHttpPool();
    }
 ***/


    /**
     * This returns the time in milliseconds that the query will wait for search results. A value of 0 means to wait
     * indefinitely.
     * 
     * @return <code>int</code> milliseconds
     */
    public int getSearchTimeLimit() {
        return searchTimeLimit;
    }

    /**
     * This sets the time in milliseconds that the ldap will wait for search results. A value of 0 means to wait
     * indefinitely. This method will remove any cached results.
     * 
     * @see #clearCache()
     * 
     * @param i <code>int</code> milliseconds
     */
    public void setSearchTimeLimit(int i) {
        searchTimeLimit = i;
        clearCache();
    }

    /**
     * This returns the maximum number of search results to return. A value of 0 all entries will be
     * returned.
     * 
     * @return <code>long</code> maximum number of search results
     */
    public long getMaxResults() {
        return maxResults;
    }

    /**
     * This sets the maximum number of search results to return. A value of 0 all entries will be returned.
     * This method will remove any cached results.
     * 
     * @see #clearCache()
     * 
     * @param l <code>long</code> maximum number of search results
     */
    public void setMaxResults(int max) {
        maxResults = max;
        clearCache();
    }

    /**
     * This returns the basic authn username.
     * 
     * @return <code>String</code> username
     */
    public String getUsername() {
        return username;
    }

    /**
     * This sets the basic auth username
     * 
     * @param s <code>String</code> username
     */
    public void setUsername(String u) {
        username = u;
        // initializeConnectionManager();
    }

    /**
     * This returns the basic authn password
     * 
     * @return <code>String</code> principal credential
     */
    public String getPassword() {
        return password;
    }

    /**
     * This sets the basic auth password
     * 
     * @param s <code>String</code> password
     */
    public void setPassword(String p) {
        password = p;
        // initializeConnectionManager();
    }

    public void setRwsAttributes(List<RwsAttribute> list) {
       rwsAttributes = list;
    }
    public void setConfiguredActivators(List<String> v) {
       configuredActivators = v;
    }
    public void setActivatorsFilename(String v) {
       activatorsFilename = v;
    }
    public void setPollingFrequency(int v) {
       pollingFrequency = v;
    }

   // check the activators file for changes
   public void refreshActivators() {

      if (activatorsFilename==null) return;  // no file

      Date nowDate = new Date();
      long now = nowDate.getTime();
      if (now < ( activatorsChecked + pollingFrequency ) ) return;

      try {
         File af = new File(activatorsFilename);
         if (activatorsModified < af.lastModified()) {
            log.debug("refreshing activators from: " + activatorsFilename);
            activatorsModified = af.lastModified();
            List<String> newActivators = new Vector<String>(configuredActivators);

            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
   	    Document doc = dBuilder.parse(af);
   	    doc.getDocumentElement().normalize();
 
   	    NodeList rpNodes = doc.getElementsByTagName("ActivationRequirement");
 
   	    for (int i=0; i<rpNodes.getLength(); i++) {
   	       Node rpNode = rpNodes.item(i);
   	       if (rpNode.getNodeType() == Node.ELEMENT_NODE) {
   	          String rp = ((Element)rpNode).getAttribute("entityId");
                  if (rp.length()>0) newActivators.add(rp);
                  log.debug("adding activator: " + rp);
               }
   	    }
            activators = newActivators;
   	 }

      } catch (IOException e) {
         log.error("could not read activators file: " + e);
      } catch (ParserConfigurationException e) {
         log.error("parse cofig activators file: " + e);
      } catch (SAXException e) {
         log.error("could not parse activators file: " + e);
      }
      activatorsChecked = now;
   }

}
