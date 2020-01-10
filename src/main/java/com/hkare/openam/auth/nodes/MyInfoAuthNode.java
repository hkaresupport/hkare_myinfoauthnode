package com.hkare.openam.auth.nodes;
/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2018-2019 ForgeRock AS.
 */

import static com.hkare.openam.auth.nodes.SocialOAuth2Helper.ATTRIBUTES_SHARED_STATE_KEY;
import static com.hkare.openam.auth.nodes.SocialOAuth2Helper.USER_INFO_SHARED_STATE_KEY;
import static com.hkare.openam.auth.nodes.SocialOAuth2Helper.USER_NAMES_SHARED_STATE_KEY;
import static java.util.Collections.singletonList;
import static java.util.stream.Collectors.toMap;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.openam.auth.node.api.Action.goTo;
import static org.forgerock.openam.auth.node.api.Action.send;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.EMAIL_ADDRESS;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.stream.Collectors;

import javax.inject.Inject;
import javax.security.auth.callback.Callback;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.oauth.DataStore;
import org.forgerock.oauth.OAuthClient;
import org.forgerock.oauth.OAuthClientConfiguration;
import org.forgerock.oauth.OAuthException;
import org.forgerock.oauth.UserInfo;
import org.forgerock.oauth.clients.oauth2.OAuth2ClientConfiguration;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.ExternalRequestContext;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.OutcomeProvider;
import org.forgerock.openam.auth.node.api.SharedStateConstants;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.authentication.modules.common.mapping.AccountProvider;
import org.forgerock.openam.sm.annotations.adapters.Password;
import org.forgerock.openam.sm.validation.URLValidator;
import org.forgerock.util.i18n.PreferredLocales;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import com.hkare.openam.auth.nodes.util.MyInfoConstants;
import com.hkare.openam.auth.nodes.util.MyInfoCryptoUtil;
import com.hkare.openam.auth.nodes.util.MyInfoJsonUtil;
import com.iplanet.am.util.SystemProperties;
import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.authentication.spi.RedirectCallback;
import com.sun.identity.shared.Constants;
import com.sun.identity.sm.RequiredValueValidator;

/**
 * This class serves as a base for social authentication login node.
 */
@Node.Metadata(outcomeProvider = MyInfoAuthNode.SocialAuthOutcomeProvider.class, configClass = MyInfoAuthNode.Config.class)
public class MyInfoAuthNode implements Node {
	private static final String BUNDLE = "org/forgerock/openam/auth/nodes/AbstractSocialAuthLoginNode";
	private static final String MIX_UP_MITIGATION_PARAM_CLIENT_ID = "client_id";
	private static final String MIX_UP_MITIGATION_PARAM_ISSUER = "iss";
	private static final String MAIL_KEY_MAPPING = "mail";

	private static final boolean KEY_BASIC_AUTH = true;
	private static final String KEY_SOCIAL_PROVIDER = "MyInfo";
	private static final boolean KEY_SAVE_USER_ATTRIBUTES_TO_SESSION = false;
	private static final boolean KEY_CFG_MIX_UP_MITIGATION = false;
	private static final Object KEY_TOKEN_ISSUER = "";

	private static final String KEY_CFG_ACCOUNT_PROVIDER_CLASS = "org.forgerock.openam.authentication.modules.common.mapping.DefaultAccountProvider";
	public static final String KEY_CFG_ACCOUNT_MAPPER_CLASS = "org.forgerock.openam.authentication.modules.common.mapping.JsonAttributeMapper";
	private static final String KEY_AUTHENTICATION_ID_KEY = "sub";

	private final MyInfoAuthNode.Config config;
	private final ProfileNormalizer profileNormalizer;
	private final Logger logger = LoggerFactory.getLogger("amAuth");
	private final OAuthClient client;
	private final SocialOAuth2Helper authModuleHelper;

	/**
	 * The interface Config.
	 */
	public interface Config {

		/**
		 * the client id.
		 * 
		 * @return the client id
		 */
		@Attribute(order = 100, validators = { RequiredValueValidator.class })
		String clientId();

		/**
		 * The client secret.
		 * 
		 * @return the client secret
		 */
		@Attribute(order = 200, validators = { RequiredValueValidator.class })
		@Password
		char[] clientSecret();

		/**
		 * The authorization endpoint.
		 * 
		 * @return The authorization endpoint.
		 */
		@Attribute(order = 300, validators = { RequiredValueValidator.class, URLValidator.class })
		String authorizeEndpoint();

		/**
		 * The token endpoint.
		 * 
		 * @return The token endpoint.
		 */
		@Attribute(order = 400, validators = { RequiredValueValidator.class, URLValidator.class })
		String tokenEndpoint();

		/**
		 * The userinfo endpoint.
		 * 
		 * @return the userinfo endpoint.
		 */
		@Attribute(order = 500, validators = { RequiredValueValidator.class, URLValidator.class })
		String userInfoEndpoint();

		/**
		 * The scopes to request.
		 * 
		 * @return the scopes.
		 */
		@Attribute(order = 600, validators = { RequiredValueValidator.class })
		String scopeString();

		/**
		 * The Purpose.
		 * 
		 * @return the purpose.
		 */
		@Attribute(order = 700, validators = { RequiredValueValidator.class })
		String purpose();

		/**
		 * The URI the AS will redirect to.
		 * 
		 * @return the redirect URI
		 */
		@Attribute(order = 800, validators = { RequiredValueValidator.class, URLValidator.class })
		String redirectURI();

		/**
		 * The authentication id key.
		 * 
		 * @return the authentication id key.
		 */
		@Attribute(order = 900, validators = { RequiredValueValidator.class })
		String authenticationIdKey();

		/**
		 * KeyStore Location.
		 * 
		 * @return teh authentication id key.
		 */
		@Attribute(order = 1000, validators = { RequiredValueValidator.class })
		String pathToKeyStore();

		/**
		 * KeyStore Password
		 * 
		 * @return teh authentication id key.
		 */
		@Attribute(order = 1100, validators = { RequiredValueValidator.class })
		@Password
		char[] keyStorePassword();

		/**
		 * MyInfo SigningCert Alias Name.
		 * 
		 * @return the authentication id key.
		 */
		@Attribute(order = 1200, validators = { RequiredValueValidator.class })
		String myInfoSigningCertAlias();

		/**
		 * The account mapper configuration.
		 * 
		 * @return the account mapper configuration.
		 */
		@Attribute(order = 1300, validators = { RequiredValueValidator.class })

		Map<String, String> cfgAccountMapperConfiguration();

		/**
		 * The attribute mapping configuration.
		 * 
		 * @return the attribute mapping configuration
		 */
		@Attribute(order = 1400, validators = { RequiredValueValidator.class })
		Map<String, String> cfgAttributeMappingConfiguration();

		/**
		 * The account provider class.
		 * 
		 * @return The account provider class.
		 */
		default String cfgAccountProviderClass() {
			return KEY_CFG_ACCOUNT_PROVIDER_CLASS;
		}

		/**
		 * The account mapper class.
		 * 
		 * @return the account mapper class.
		 */
		default String cfgAccountMapperClass() {
			return KEY_CFG_ACCOUNT_MAPPER_CLASS;
		}

		/**
		 * The attribute mapping classes.
		 * 
		 * @return the attribute mapping classes.
		 */
		default Set<String> cfgAttributeMappingClasses() {
			Set<String> attributeMapping = new HashSet<String>();
			attributeMapping.add(KEY_CFG_ACCOUNT_MAPPER_CLASS);
			return attributeMapping;
		}

	}

	/**
	 * Constructs a new {@link MyInfoAuthNode} with the provided
	 * {@link MyInfoAuthNode.Config}.
	 *
	 * @param config            provides the settings for initialising an
	 *                          {@link MyInfoAuthNode}.
	 * @param authModuleHelper  a social oauth2 helper.
	 * @param client            The oauth client to use. That's the client
	 *                          responsible to deal with the oauth workflow.
	 * @param profileNormalizer User profile normaliser
	 */
	@Inject
	public MyInfoAuthNode(@Assisted MyInfoAuthNode.Config config, SocialOAuth2Helper authModuleHelper,
			ProfileNormalizer profileNormalizer) {
		logger.debug("****initialize MyInfo Node constructor.*************");
		this.config = config;
		this.authModuleHelper = authModuleHelper;
		this.client = authModuleHelper.newOAuthClient(getOAuthClientConfiguration(config));
		this.profileNormalizer = profileNormalizer;
	}

	private OAuthClientConfiguration getOAuthClientConfiguration(MyInfoAuthNode.Config config) {
		logger.debug("*****getOAuthClientConfiguration****");
		return OAuth2ClientConfiguration.oauth2ClientConfiguration().withClientId(config.clientId())
				.withClientSecret(new String(config.clientSecret()))
				.withAuthorizationEndpoint(config.authorizeEndpoint()).withTokenEndpoint(config.tokenEndpoint())
				.withScope(Collections.singletonList(config.scopeString())).withScopeDelimiter(",")
				.withBasicAuth(KEY_BASIC_AUTH).withUserInfoEndpoint(config.userInfoEndpoint())
				.withRedirectUri(URI.create(config.redirectURI())).withProvider(KEY_SOCIAL_PROVIDER)
				.withAuthenticationIdKey(config.authenticationIdKey()).build();
	}

	@Override
	public Action process(TreeContext context) throws NodeProcessException {
		logger.debug("****Start process*****");
		if (context.request.parameters.containsKey("code")) {
			logger.debug("contains key = code**********");
			logger.debug("the request parameters contains a code");

			return processOAuthTokenState(context);
		}

		DataStore dataStore = SharedStateAdaptor.toDatastore(json(context.sharedState));
		Callback callback = prepareRedirectCallback(dataStore);
		return send(callback).replaceSharedState(SharedStateAdaptor.fromDatastore(dataStore)).build();
	}

	/**
	 * Constructs the server URL using the AM server protocol, host, port and
	 * services deployment descriptor from {@link SystemProperties}. If any of these
	 * properties are not available, an empty string is returned instead.
	 *
	 * @return The server URL.
	 */
	protected static String getServerURL() {
		final String protocol = SystemProperties.get(Constants.AM_SERVER_PROTOCOL);
		final String host = SystemProperties.get(Constants.AM_SERVER_HOST);
		final String port = SystemProperties.get(Constants.AM_SERVER_PORT);
		final String descriptor = SystemProperties.get(Constants.AM_SERVICES_DEPLOYMENT_DESCRIPTOR);

		if (protocol != null && host != null && port != null && descriptor != null) {
			return protocol + "://" + host + ":" + port + descriptor;
		} else {
			return "";
		}
	}

	private Callback prepareRedirectCallback(DataStore dataStore) throws NodeProcessException {
		RedirectCallback redirectCallback;
		try {
			URI uri = client.getAuthRedirect(dataStore, null, null).getOrThrow();

			logger.debug("prepareRedirectCallback-uri" + uri.toString());

			String state = uri.toString().substring(uri.toString().indexOf("state"));
			logger.debug("state of the::" + state);
			String[] statevals = state.split("=");
			logger.debug("statevals::" + statevals);

			String authoriseURI = config.authorizeEndpoint();
			String client_ID = config.clientId();
			String attributes = config.scopeString();
			String redirectURI = config.redirectURI();
			String purpose = config.purpose();

			String customURI = authoriseURI + "?" + MyInfoConstants.KEY_CLIENT_ID + "=" + client_ID + "&"
					+ MyInfoConstants.KEY_ATTRIBUTES + "=" + attributes + "&" + MyInfoConstants.KEY_REDIRECT_URI + "="
					+ redirectURI + "&" + MyInfoConstants.KEY_PURPOSE + "=" + purpose + "&" + MyInfoConstants.KEY_STATE
					+ "=" + statevals[1];
			try {
				uri = new URI(customURI);
			} catch (URISyntaxException e) {
				e.printStackTrace();
			}

			redirectCallback = new RedirectCallback(uri.toString(), null, MyInfoConstants.KEY_HTTP_GET);
			redirectCallback.setTrackingCookie(true);
		} catch (InterruptedException | OAuthException e) {
			throw new NodeProcessException(e);
		}

		return redirectCallback;
	}

	/*
	 * 1. Get the userInformation by calling the token endpoint to fetch the access
	 * token and then call the userEndpoint. 2. Parse the user information with the
	 * mapping supplied in the configuration to populate two map 2.1 attributes are
	 * the user information to add the profile 2.2 userNames are the information
	 * used to look up a user. 3. If a profile is found for the information in
	 * userNames then we return an ACCOUNT_EXISTS outcome otherwise we store the
	 * attributes and userNames in the sharedState and return a NO_ACCOUNT outcome
	 * 
	 */
	private Action processOAuthTokenState(TreeContext context) throws NodeProcessException {
		performMixUpMitigationProtectionCheck(context.request);

		Optional<String> user;
		Map<String, Set<String>> attributes;
		Map<String, Set<String>> userNames;
		try {
			UserInfo userInfo = getUserInfo(context);

			attributes = profileNormalizer.getNormalisedAttributes(userInfo, getJwtClaims(userInfo), config);
			userNames = profileNormalizer.getNormalisedAccountAttributes(userInfo, getJwtClaims(userInfo), config);
			logger.debug("attributes----::" + attributes);
			addLogIfTooManyUsernames(userNames, userInfo);
			logger.debug("userNames----::" + userNames);
			AccountProvider accountProvider = profileNormalizer.getAccountProvider(config);
//			accountProvider.
			user = authModuleHelper.userExistsInTheDataStore(context.sharedState.get("realm").asString(),
					profileNormalizer.getAccountProvider(config), userNames);

			logger.debug("user----::" + user);
		} catch (AuthLoginException e) {
			throw new NodeProcessException(e);
		}

		return getAction(context, user, attributes, userNames);
	}

	/**
	 * Making this protected allows other Social Nodes (specifically the Social
	 * OpenId Connect node) to provide their own implementations.
	 * 
	 * @param userInfo The user information.
	 * @return The jwt claims.
	 */
	protected JwtClaimsSet getJwtClaims(UserInfo userInfo) {
		return null;
	}

	private void addLogIfTooManyUsernames(Map<String, Set<String>> userNames, UserInfo userInfo) {
		if (userNames.values().size() > 1) {
			if (logger.isWarnEnabled()) {
				String usernamesAsString = config.cfgAccountMapperConfiguration().entrySet().stream()
						.map(entry -> entry.getKey() + " - " + entry.getValue()).collect(Collectors.joining(", "));
				logger.warn("Multiple usernames have been found for the user information {} with your configuration "
						+ "mapping {}", userInfo.toString(), usernamesAsString);
			}
		}
	}

	private Action getAction(TreeContext context, Optional<String> user, Map<String, Set<String>> attributes,
			Map<String, Set<String>> userNames) {
		Action.ActionBuilder action;
		if (user.isPresent()) {
			logger.debug("The user {} already have an account. Go to {} outcome", user.get(),
					SocialAuthOutcome.ACCOUNT_EXISTS.name());

			action = goTo(SocialAuthOutcome.ACCOUNT_EXISTS.name())
					.replaceSharedState(context.sharedState.add(SharedStateConstants.USERNAME, user.get()));
		} else {
			logger.debug("The user doesn't have an account");

			JsonValue sharedState = context.sharedState.put(USER_INFO_SHARED_STATE_KEY,
					json(object(field(ATTRIBUTES_SHARED_STATE_KEY, convertToMapOfList(attributes)),
							field(USER_NAMES_SHARED_STATE_KEY, convertToMapOfList(userNames)))));

			if (attributes.get(MAIL_KEY_MAPPING) != null) {
				sharedState = sharedState.add(EMAIL_ADDRESS, attributes.get(MAIL_KEY_MAPPING).stream().findAny().get());
			} else {
				logger.debug("Unable to ascertain email address because the information is not available. "
						+ "It's possible you need to add a scope or that the configured provider does not have this "
						+ "information");
			}

			logger.debug("Go to " + SocialAuthOutcome.NO_ACCOUNT.name() + " outcome");
			action = goTo(SocialAuthOutcome.NO_ACCOUNT.name()).replaceSharedState(sharedState);
		}

		if (KEY_SAVE_USER_ATTRIBUTES_TO_SESSION) {
			logger.debug("user attributes are going to be saved in the session");
			attributes.forEach((key, value) -> action.putSessionProperty(key, value.stream().findFirst().get()));
		}
		return action.build();
	}

	private void performMixUpMitigationProtectionCheck(ExternalRequestContext request) throws NodeProcessException {
		if (KEY_CFG_MIX_UP_MITIGATION) {
			List<String> clientId = request.parameters.get(MIX_UP_MITIGATION_PARAM_CLIENT_ID);
			if (clientId == null || clientId.size() != 1) {
				throw new NodeProcessException("OAuth 2.0 mix-up mitigation is enabled, but the client_id has not been "
						+ "provided properly");
			} else if (!config.clientId().equals(clientId.get(0))) {
				throw new NodeProcessException("OAuth 2.0 mix-up mitigation is enabled, but the provided client_id "
						+ clientId.get(0) + " does not belong to this client " + config.clientId());
			}

			List<String> issuer = request.parameters.get(MIX_UP_MITIGATION_PARAM_ISSUER);
			if (issuer == null || issuer.size() != 1) {
				throw new NodeProcessException(
						"OAuth 2.0 mix-up mitigation is enabled, but the iss has not been " + "provided properly");
			} else if (!KEY_TOKEN_ISSUER.equals(issuer.get(0))) {
				throw new NodeProcessException("OAuth 2.0 mix-up mitigation is enabled, but the provided iss "
						+ issuer.get(0) + " does not match the issuer in the client configuration " + KEY_TOKEN_ISSUER);
			}
		}
	}

	private Map<String, ArrayList<String>> convertToMapOfList(Map<String, Set<String>> mapToConvert) {
		return mapToConvert.entrySet().stream().collect(toMap(Map.Entry::getKey, e -> new ArrayList<>(e.getValue())));
	}

	private UserInfo getUserInfo(TreeContext context) throws NodeProcessException {
		logger.debug("******getUserInfo*********..");
		DataStore dataStore = SharedStateAdaptor.toDatastore(context.sharedState);
		try {
			if (!context.request.parameters.containsKey("state")) {
				throw new NodeProcessException(
						"Not having the state could mean that this request did not come from " + "the IDP");
			}
			HashMap<String, List<String>> parameters = new HashMap<>();
			String state = context.request.parameters.get("state").get(0);
			String code = context.request.parameters.get("code").get(0);
			parameters.put("state", singletonList(state));
			parameters.put("code", singletonList(code));

			logger.debug("fetching the access token ..." + parameters);
			// fetch user profile information with token
			UserInfo userinfo = queryProfileWithAccessToken(code, state, dataStore);
			logger.debug("userinfo********::" + userinfo.getSubject());
			return userinfo;
		} catch (Exception e) {
			throw new NodeProcessException("Unable to get UserInfo details from provider", e);
		}
	}

	/**
	 * @param accessToken
	 * @param code
	 * @param state
	 * @param dataStore
	 * @return
	 * @throws NodeProcessException
	 */
	private UserInfo queryProfileWithAccessToken(String code, String state, DataStore dataStore)
			throws NodeProcessException {
		String profileURI = config.userInfoEndpoint();
		String client_ID = config.clientId();
		String subject = null;
		String attributes = null;
		logger.debug("profileURI :" + profileURI + "client_ID77..:" + client_ID);
		UserInfo userInfo = null;
		HttpGet userInfoRequest = null;
		try {

			Map<String, String> accessTokenInfo = this.getAccessTokenInfo(code, state, dataStore);

			String accessToken = accessTokenInfo.get("access_token");

			logger.debug("accessToken:" + accessToken);
			subject = accessTokenInfo.get("subject");
			logger.debug("subject--::" + subject);
			attributes = config.scopeString();
			logger.debug("attributes to proces::" + attributes);
			String finalURL = profileURI + "/" + subject + "?client_id=" + client_ID + "&attributes=" + attributes;
			logger.debug("finalURL to fetch::" + finalURL);

			userInfoRequest = new HttpGet(finalURL);
			userInfoRequest.addHeader("Authorization", "Bearer " + accessToken);
			CloseableHttpClient httpClient = HttpClients.createDefault();
			try (CloseableHttpResponse response = httpClient.execute(userInfoRequest)) {

				// Get HttpResponse Status
				logger.debug("response code::" + response.getStatusLine().toString());

				HttpEntity entity = response.getEntity();
				Header headers = entity.getContentType();
				logger.debug("headers:" + headers);

				if (entity != null) {
					// return it as a String
					String result = EntityUtils.toString(entity);
					logger.debug(result);
					JsonValue storeJson = MyInfoJsonUtil.parseResponseJson(result, config.scopeString(), subject);
					logger.debug("**response Json value:" + storeJson);
					userInfo = new MyInfoOAuthUserInfo("sub", storeJson);
				}

			}
		} catch (Exception e) {
			throw new NodeProcessException("Unable to get UserInfo details from provider", e);
		}
		return userInfo;
	}

	/**
	 * @param code
	 * @param state
	 * @param dataStore
	 * @return
	 * @throws InvalidKeyException
	 * @throws Exception
	 */
	private Map<String, String> getAccessTokenInfo(String code, String state, final DataStore dataStore)
			throws InvalidKeyException, Exception {

		Map<String, String> accessTokenInfo = new HashMap<String, String>();

		try {

			HttpPost httpPost = new HttpPost(config.tokenEndpoint());
			httpPost.addHeader("Content-Type", "application/x-www-form-urlencoded");

			// add request parameter, form parameters
			List<NameValuePair> urlParameters = new ArrayList<>();
			urlParameters.add(new BasicNameValuePair("grant_type", MyInfoConstants.KEY_AUTHORIZATION_CODE_GRANT));
			urlParameters.add(new BasicNameValuePair("redirect_uri", config.redirectURI()));
			urlParameters.add(new BasicNameValuePair("client_id", config.clientId()));
			urlParameters.add(new BasicNameValuePair("client_secret", new String(config.clientSecret())));
			urlParameters.add(new BasicNameValuePair("state", state));
			urlParameters.add(new BasicNameValuePair("code", code));

			httpPost.setEntity(new UrlEncodedFormEntity(urlParameters));

			CloseableHttpClient httpClient = HttpClients.createDefault();

			try (CloseableHttpResponse response = httpClient.execute(httpPost)) {

				String responseStr = EntityUtils.toString(response.getEntity());

				JSONObject obj = new JSONObject(responseStr);

				String keyStoreLocation = config.pathToKeyStore();
				String password = new String(config.keyStorePassword());
				String keyAlias = config.myInfoSigningCertAlias();

				accessTokenInfo.put("access_token", obj.getString("access_token"));

				// validate the json and get subject
				String subject = MyInfoCryptoUtil.validateAccessToken(obj.getString("access_token"), keyStoreLocation,
						password, keyAlias);

				accessTokenInfo.put("subject", subject);

				logger.debug("isValidToken: -subject:" + subject);

				logger.debug("Status code::" + response.getStatusLine().getStatusCode());
			}
		} catch (Exception e) {
			throw new NodeProcessException("Unable to get access token ", e);
		}
		return accessTokenInfo;
	}

	/**
	 * The possible outcomes for the AbstractSocialAuthLoginNode.
	 */
	public enum SocialAuthOutcome {
		/**
		 * Successful authentication.
		 */
		ACCOUNT_EXISTS,
		/**
		 * Authentication failed.
		 */
		NO_ACCOUNT
	}

	/**
	 * Defines the possible outcomes from this node.
	 */
	public static class SocialAuthOutcomeProvider implements OutcomeProvider {
		@Override
		public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
			ResourceBundle bundle = locales.getBundleInPreferredLocale(MyInfoAuthNode.BUNDLE,
					MyInfoAuthNode.SocialAuthOutcomeProvider.class.getClassLoader());
			return ImmutableList.of(
					new Outcome(MyInfoAuthNode.SocialAuthOutcome.ACCOUNT_EXISTS.name(),
							bundle.getString("accountExistsOutcome")),
					new Outcome(MyInfoAuthNode.SocialAuthOutcome.NO_ACCOUNT.name(),
							bundle.getString("noAccountOutcome")));
		}
	}
}
