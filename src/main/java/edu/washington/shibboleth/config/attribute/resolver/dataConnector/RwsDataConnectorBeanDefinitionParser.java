/* ========================================================================
 * Copyright (c) 2010 The University of Washington
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

import java.util.HashMap;
import java.util.List;
import java.util.Vector;
import java.util.Map;
import java.util.StringTokenizer;

import javax.xml.namespace.QName;

import org.opensaml.xml.util.DatatypeHelper;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.ParserContext;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.common.config.SpringConfigurationUtils;

import edu.internet2.middleware.shibboleth.common.config.attribute.resolver.dataConnector.BaseDataConnectorBeanDefinitionParser;
import edu.internet2.middleware.shibboleth.common.config.attribute.resolver.dataConnector.DataConnectorNamespaceHandler;

import edu.washington.shibboleth.attribute.resolver.provider.dataConnector.RwsDataConnector.AUTHENTICATION_TYPE;
import edu.washington.shibboleth.attribute.resolver.provider.dataConnector.RwsAttribute;


/** Spring bean definition parser for configuring a GWS data connector. */
public class RwsDataConnectorBeanDefinitionParser extends BaseDataConnectorBeanDefinitionParser {

    /** data connector type name. */
    public static final QName TYPE_NAME = new QName(UWDataConnectorNamespaceHandler.NAMESPACE, "WebService");

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(RwsDataConnectorBeanDefinitionParser.class);

    /** Name of resolution plug-in attribute. */
    public static final QName ATTRIBUTE_ELEMENT_NAME = new QName(UWDataConnectorNamespaceHandler.NAMESPACE,
            "Attribute");

    /** Name of resolution plug-in activation. */
    public static final QName ACTIVATION_ELEMENT_NAME = new QName(UWDataConnectorNamespaceHandler.NAMESPACE,
            "ActivationRequirement");

    /** {@inheritDoc} */
    protected Class getBeanClass(Element element) {
        return RwsDataConnectorFactoryBean.class;
    }

    /** {@inheritDoc} */
    protected void doParse(String pluginId, Element pluginConfig, Map<QName, List<Element>> pluginConfigChildren,
            BeanDefinitionBuilder pluginBuilder, ParserContext parserContext) {
        super.doParse(pluginId, pluginConfig, pluginConfigChildren, pluginBuilder, parserContext);

        List<RwsAttribute> attributes = parseAttributes(pluginConfigChildren.get(ATTRIBUTE_ELEMENT_NAME));
        log.debug("Setting the following attributes for plugin {}: {}", pluginId, attributes);
        pluginBuilder.addPropertyValue("rwsAttributes", attributes);

        String activatorsFilename = parseFileActivator(pluginConfigChildren.get(ACTIVATION_ELEMENT_NAME));
        log.debug("Data connector {} activatorsFilename: {}", pluginId, activatorsFilename);
        pluginBuilder.addPropertyValue("activatorsFilename", activatorsFilename);

        List<String> configuredActivators = parseDirectActivators(pluginConfigChildren.get(ACTIVATION_ELEMENT_NAME));
        log.debug("Setting the following activator requirements for plugin {}: {}", pluginId, configuredActivators);
        pluginBuilder.addPropertyValue("configuredActivators", configuredActivators);

        String baseURL = pluginConfig.getAttributeNS(null, "baseURL");
        log.debug("Data connector {} base URL: {}", pluginId, baseURL);
        pluginBuilder.addPropertyValue("baseUrl", baseURL);

        AUTHENTICATION_TYPE authnType = AUTHENTICATION_TYPE.NONE;
        if (pluginConfig.hasAttributeNS(null, "authenticationType")) {
            authnType = AUTHENTICATION_TYPE.valueOf(pluginConfig.getAttributeNS(null, "authenticationType"));
        }
        log.debug("Data connector {} authentication type: {}", pluginId, authnType);
        pluginBuilder.addPropertyValue("authenticationType", authnType);

        String username = pluginConfig.getAttributeNS(null, "username");
        if (username!=null) log.debug("Data connector {} username: {}", pluginId, username);
        pluginBuilder.addPropertyValue("username", username);

        String password = pluginConfig.getAttributeNS(null, "password");
        pluginBuilder.addPropertyValue("password", password);

        String queryTemplate = pluginConfigChildren.get(
                new QName(UWDataConnectorNamespaceHandler.NAMESPACE, "QueryTemplate")).get(0).getTextContent();
        queryTemplate = DatatypeHelper.safeTrimOrNullString(queryTemplate);
        if (queryTemplate!=null) log.debug("Data connector {} query template: {}", pluginId, queryTemplate);
        pluginBuilder.addPropertyValue("queryTemplate", queryTemplate);

        RuntimeBeanReference trustCredential = processCredential(pluginConfigChildren.get(new QName(
                UWDataConnectorNamespaceHandler.NAMESPACE, "TrustCredential")), parserContext);
        log.debug("Data connector {} using provided trust material", pluginId);
        pluginBuilder.addPropertyValue("trustCredential", trustCredential);

        RuntimeBeanReference connectionCredential = processCredential(pluginConfigChildren.get(new QName(
                UWDataConnectorNamespaceHandler.NAMESPACE, "AuthenticationCredential")), parserContext);
        log.debug("Data connector {} using provided client authentication material", pluginId);
        pluginBuilder.addPropertyValue("connectionCredential", connectionCredential);

        int maxConnections = 0;
        if (pluginConfig.hasAttributeNS(null, "maxConnections")) {
            maxConnections = Integer.parseInt(pluginConfig.getAttributeNS(null, "maxConnections"));
        }
        log.debug("Data connector {} max connections: {}", pluginId, maxConnections);
        pluginBuilder.addPropertyValue("maxConnections", maxConnections);

        int searchTimeLimit = 5000;
        if (pluginConfig.hasAttributeNS(null, "searchTimeLimit")) {
            searchTimeLimit = Integer.parseInt(pluginConfig.getAttributeNS(null, "searchTimeLimit"));
        }
        log.debug("Data connector {} search timeout: {}ms", pluginId, searchTimeLimit);
        pluginBuilder.addPropertyValue("searchTimeLimit", searchTimeLimit);

        int maxResultSize = 1;
        if (pluginConfig.hasAttributeNS(null, "maxResultSize")) {
            maxResultSize = Integer.parseInt(pluginConfig.getAttributeNS(null, "maxResultSize"));
        }
        log.debug("Data connector {} max search result size: {}", pluginId, maxResultSize);
        pluginBuilder.addPropertyValue("maxResultSize", maxResultSize);

        boolean cacheResults = false;
        if (pluginConfig.hasAttributeNS(null, "cacheResults")) {
            cacheResults = XMLHelper.getAttributeValueAsBoolean(pluginConfig.getAttributeNodeNS(null, "cacheResults"));
        }
        log.debug("Data connector {} cache results: {}", pluginId, cacheResults);
        pluginBuilder.addPropertyValue("cacheResults", cacheResults);

        boolean mergeResults = false;
        if (pluginConfig.hasAttributeNS(null, "mergeResults")) {
            mergeResults = XMLHelper.getAttributeValueAsBoolean(pluginConfig.getAttributeNodeNS(null, "mergeResults"));
        }
        log.debug("Data connector{} merge results: {}", pluginId, mergeResults);
        pluginBuilder.addPropertyValue("mergeResults", mergeResults);

        boolean noResultsIsError = false;
        if (pluginConfig.hasAttributeNS(null, "noResultIsError")) {
            noResultsIsError = XMLHelper.getAttributeValueAsBoolean(pluginConfig.getAttributeNodeNS(null,
                    "noResultIsError"));
        }
        log.debug("Data connector {} no results is error: {}", pluginId, noResultsIsError);
        pluginBuilder.addPropertyValue("noResultsIsError", noResultsIsError);

        int pollingFrequency = 60000;
        if (pluginConfig.hasAttributeNS(null, "pollingFrequency")) {
            pollingFrequency = Integer.parseInt(pluginConfig.getAttributeNS(null, "pollingFrequency"));
        }
        log.debug("Data connector {} polling frequency: {}ms", pluginId, pollingFrequency);
        pluginBuilder.addPropertyValue("pollingFrequency", pollingFrequency);

        String templateEngineRef = pluginConfig.getAttributeNS(null, "templateEngine");
        pluginBuilder.addPropertyReference("templateEngine", templateEngineRef);
    }


    /**
     * Processes a credential element.
     * 
     * @param credentials list containing the element to process.
     * @param parserContext current parser context
     * 
     * @return the bean definition for the credential
     */
    protected RuntimeBeanReference processCredential(List<Element> credentials, ParserContext parserContext) {
        if (credentials == null) {
            return null;
        }
        log.debug("Data connector processng a credential");
        Element credentialElem = credentials.get(0);
        return SpringConfigurationUtils.parseCustomElement(credentialElem, parserContext);
    }


    /**
     * Parse attribute requirements
     *
     * @param elements DOM elements of type <code>Attribute</code>
     *
     * @return the attributes
     */
    protected List<RwsAttribute> parseAttributes(List<Element> elements) {
        if (elements == null || elements.size() == 0) {
            return null;
        }
        List<RwsAttribute> rwsAttributes = new Vector<RwsAttribute>();
        for (Element ele : elements) {
            RwsAttribute rwsAttribute = new RwsAttribute();
            rwsAttribute.name = DatatypeHelper.safeTrimOrNullString(ele.getAttributeNS(null, "name"));
    log.debug("parseattribute: " + rwsAttribute.name);
            rwsAttribute.xPath = DatatypeHelper.safeTrimOrNullString(ele.getAttributeNS(null, "xPath"));
            rwsAttribute.maxResultSize = 1;
            if (ele.hasAttributeNS(null, "maxResultSize")) {
                   rwsAttribute.maxResultSize = Integer.parseInt(ele.getAttributeNS(null, "maxResultSize"));
            }
            boolean noResultsIsError = false;
            if (ele.hasAttributeNS(null, "noResultIsError")) {
                   rwsAttribute.noResultIsError = XMLHelper.getAttributeValueAsBoolean(ele.getAttributeNodeNS(null, "noResultIsError"));
            }
            rwsAttributes.add(rwsAttribute);
        }
        return rwsAttributes;
    }

    /**
     * Parse activation requirements for entityids
     *
     * @param elements DOM elements of type <code>ActivationRequirement</code>
     *
     * @return the direct activators
     */
    protected List<String> parseDirectActivators(List<Element> elements) {
        List<String> activators = new Vector<String>();
        if (elements != null && elements.size() > 0) {
           for (Element activator : elements) {
               String rp = DatatypeHelper.safeTrimOrNullString(activator.getAttributeNS(null, "entityId"));
               if (rp!=null) {
                  log.debug("adding.. " + rp);
                  activators.add(rp);
               }
           }
        }
        return activators;
    }


    /**
     * Parse activation requirements for file
     *
     * @param elements DOM elements of type <code>ActivationRequirement</code>
     *
     * @return the filename or null
     */
    protected String parseFileActivator(List<Element> elements) {
        String filename = null;
        if (elements != null && elements.size() > 0) {
           for (Element activator : elements) {
               filename = DatatypeHelper.safeTrimOrNullString(activator.getAttributeNS(null, "file"));
               if (filename!=null) break;
           }

        }
        log.debug("activator resource file: " + filename);
        return filename;
    }
}
