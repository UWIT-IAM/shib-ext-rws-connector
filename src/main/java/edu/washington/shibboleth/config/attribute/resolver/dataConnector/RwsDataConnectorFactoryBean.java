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

package edu.washington.shibboleth.config.attribute.resolver.dataConnector;

import java.util.Map;
import java.util.List;

import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.util.DatatypeHelper;

import edu.internet2.middleware.shibboleth.common.attribute.resolver.provider.dataConnector.TemplateEngine;
import edu.internet2.middleware.shibboleth.common.config.attribute.resolver.dataConnector.BaseDataConnectorFactoryBean;

import edu.washington.shibboleth.attribute.resolver.provider.dataConnector.RwsAttribute;
import edu.washington.shibboleth.attribute.resolver.provider.dataConnector.RwsDataConnector;
import edu.washington.shibboleth.attribute.resolver.provider.dataConnector.RwsDataConnector.AUTHENTICATION_TYPE;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Spring factory for creating {@link RwsDataConnector} beans.
 */
public class RwsDataConnectorFactoryBean extends BaseDataConnectorFactoryBean {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(RwsDataConnectorFactoryBean.class);

    /** Template engine used to construct filter queries. */
    private TemplateEngine templateEngine;

    /** return attribute name. */
    private List<RwsAttribute> rwsAttributes;

    /** base URL of the server. */
    private String baseURL;

    /** username if basic auth. */
    private String username;

    /** password if basic auth. */
    private String password;
    
    /** authentication type. */
    private AUTHENTICATION_TYPE authenticationType;

    /** query template. */
    private String queryTemplate;

    /** Trust material used when connecting to the server over https. */
    private X509Credential trustCredential;

    /** Client authentication material used when using client certificate auth. */
    private X509Credential connectionCredential;

    /** Max connections */
    private int maxConnections;

    /** Time, in milliseconds, to wait for a search to return. */
    private int searchTimeLimit;

    /** Maximum number of results to return. */
    private int maxResultSize;

    /** Whether to cache query the results. */
    private boolean cacheResults;

    /** Whether to merge multiple results into a single set of attributes. */
    private boolean mergeResults;

    /** Whether a search returning no results should be considered an error. */
    private boolean noResultsIsError;

    /** File with activation RPs  */
    private String activatorsFilename;

    /** Time, in milliseconds, to wait before checking the activators file for changes. */
    private int pollingFrequency;

    /** Entity ids of configured activation RPs */
    private List<String> configuredActivators;

    /** {@inheritDoc} */
    protected Object createInstance() throws Exception {
        RwsDataConnector connector = new RwsDataConnector(baseURL, maxConnections);
        populateDataConnector(connector);
        connector.setAuthenticationType(authenticationType);
        connector.setUsername(username);
        connector.setPassword(password);
        
        if(trustCredential != null){
            connector.setSslTrustManagers(trustCredential);
        }
        
        if(connectionCredential != null){
            connector.setSslKeyManagers(connectionCredential);
        }
        
        connector.setCacheResults(cacheResults);
        connector.setQueryTemplate(queryTemplate);
        connector.setMergeResults(mergeResults);
        connector.setNoResultsIsError(noResultsIsError);
        connector.setSearchTimeLimit(searchTimeLimit);
        connector.setTemplateEngine(templateEngine);
        connector.setRwsAttributes(rwsAttributes);
        connector.setActivatorsFilename(activatorsFilename);
        connector.setConfiguredActivators(configuredActivators);

        log.debug("RwsDataConnectorFactoryBean initing");
        connector.initialize();
        return connector;
    }

    /**
     * Gets the authentication type used when connecting to the directory.
     * 
     * @return authentication type used when connecting to the directory
     */
    public AUTHENTICATION_TYPE getAuthenticationType() {
        return authenticationType;
    }
    
    /**
     * Gets the client authentication material used when connecting to the LDAP via SSL or TLS.
     * 
     * @return client authentication material used when connecting to the LDAP via SSL or TLS
     */
    public X509Credential getConnectionCredential() {
        return connectionCredential;
    }

    /**
     * Gets the query template.
     * 
     * @return query template
     */
    public String getQueryTemplate() {
        return queryTemplate;
    }

    /**
     * Gets the base URL
     * 
     * @return base URL
     */
    public String getBaseUrl() {
        return baseURL;
    }

    /**
     * Gets the maximum number of results to return from a query.
     * 
     * @return maximum number of results to return from a query
     */
    public int getMaxResultSize() {
        return maxResultSize;
    }

    /** {@inheritDoc} */
    public Class getObjectType() {
        return RwsDataConnector.class;
    }

    /**
     * Gets the max connections
     * 
     * @return max connections
     */
    public int getMaxConnections() {
        return maxConnections;
    }

    /**
     * Gets the principal DN used to bind to the directory.
     * 
     * @return principal DN used to bind to the directory
     */
    public String getUsername() {
        return username;
    }

    /**
     * Gets the credential of the principal DN used to bind to the directory.
     * 
     * @return credential of the principal DN used to bind to the directory
     */
    public String getPassword() {
        return password;
    }

    /**
     * Gets the maximum amount of time, in milliseconds, to wait for a search to complete.
     * 
     * @return maximum amount of time, in milliseconds, to wait for a search to complete
     */
    public int getSearchTimeLimit() {
        return searchTimeLimit;
    }

    /**
     * Gets the template engine used to construct query filters.
     * 
     * @return template engine used to construct query filters
     */
    public TemplateEngine getTemplateEngine() {
        return templateEngine;
    }

    /**
     * Gets the trust material used when connecting to the LDAP via SSL or TLS.
     * 
     * @return trust material used when connecting to the LDAP via SSL or TLS
     */
    public X509Credential getTrustCredential() {
        return trustCredential;
    }

    /**
     * Gets whether to cache query results.
     * 
     * @return whether to cache query results.
     */
    public boolean isCacheResults() {
        return cacheResults;
    }

    /**
     * Gets whether to merge multiple results into a single result.
     * 
     * @return whether to merge multiple results into a single result
     */
    public boolean isMergeResults() {
        return mergeResults;
    }

    /**
     * Gets whether a query that returns no results is an error condition.
     * 
     * @return whether a query that returns no results is an error condition
     */
    public boolean isNoResultsIsError() {
        return noResultsIsError;
    }

    /**
     * Sets the authentication type used when connecting to the directory.
     * 
     * @param type authentication type used when connecting to the directory
     */
    public void setAuthenticationType(AUTHENTICATION_TYPE type) {
        authenticationType = type;
    }

    /**
     * Sets whether to cache query results.
     * 
     * @param cache whether to cache query results
     */
    public void setCacheResults(boolean cache) {
        cacheResults = cache;
    }

    /**
     * Sets the client authentication material used when using client cert
     * 
     * @param credential client authentication material used when using client cert
     */
    public void setConnectionCredential(X509Credential credential) {
        connectionCredential = credential;
    }

    /**
     * Sets the query filter template.
     * 
     * @param template query filter template
     */
    public void setQueryTemplate(String template) {
        queryTemplate = DatatypeHelper.safeTrimOrNullString(template);
    }

    /**
     * Sets the base server's URL.
     * 
     * @param url base server's URL
     */
    public void setBaseUrl(String url) {
        baseURL = DatatypeHelper.safeTrimOrNullString(url);
    }

    /**
     * Sets the maximum number of results to return from a query.
     * 
     * @param max maximum number of results to return from a query
     */
    public void setMaxResultSize(int max) {
        maxResultSize = max;
    }

    /**
     * Sets whether to merge multiple results into a single result.
     * 
     * @param merge Twhether to merge multiple results into a single result
     */
    public void setMergeResults(boolean merge) {
        mergeResults = merge;
    }

    /**
     * Sets whether a query that returns no results is an error condition.
     * 
     * @param isError whether a query that returns no results is an error condition
     */
    public void setNoResultsIsError(boolean isError) {
        noResultsIsError = isError;
    }

    /**
     * Sets the max connections
     * 
     * @param max max connections
     */
    public void setMaxConnections(int max) {
        maxConnections = max;
    }

    /**
     * Sets the username for basic auth
     * 
     * @param username username for basic auth
     */
    public void setUsername(String v) {
        username = DatatypeHelper.safeTrimOrNullString(v);
    }

    /**
     * Sets the password for basic auth
     * 
     * @param password password for basic auth
     */
    public void setPassword(String v) {
        password = DatatypeHelper.safeTrimOrNullString(v);
    }

    /**
     * Sets the maximum amount of time, in milliseconds, to wait for a search to complete.
     * 
     * @param timeLimit maximum amount of time, in milliseconds, to wait for a search to complete
     */
    public void setSearchTimeLimit(int timeLimit) {
        searchTimeLimit = timeLimit;
    }

    /**
     * Sets the template engine used to construct query filters.
     * 
     * @param engine template engine used to construct query filters
     */
    public void setTemplateEngine(TemplateEngine engine) {
        templateEngine = engine;
    }

    /**
     * Sets the trust material used when connecting to the LDAP via SSL or TLS.
     * 
     * @param credential trust material used when connecting to the LDAP via SSL or TLS
     */
    public void setTrustCredential(X509Credential credential) {
        trustCredential = credential;
    }

    /**
     * Sets the attribute list
     * 
     * @param list list of attribute
     */
    public void setRwsAttributes(List<RwsAttribute> list) {
        rwsAttributes = list;
    }
    public List<RwsAttribute> getRwsAttributes() {
        return rwsAttributes;
    }
    
    /**
     * Sets the activations filename
     * 
     * @param filename with activation RP list
     */
    public void setActivatorsFilename(String v) {
        activatorsFilename = DatatypeHelper.safeTrimOrNullString(v);
    }

    /**
     * Sets the activations file pooling frequency
     * 
     * @param time in milliseconds
     */
    public void setPollingFrequency(int v) {
        pollingFrequency = v;
    }

    /**
     * Sets the activation list
     * 
     * @param list list of activation
     */
    public void setConfiguredActivators(List<String> list) {
        configuredActivators = list;
    }

/**
    public List<String> getActivators() {
        return activators;
    }
 **/
    
}
