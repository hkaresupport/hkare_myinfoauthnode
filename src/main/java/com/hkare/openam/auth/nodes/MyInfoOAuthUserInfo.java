package com.hkare.openam.auth.nodes;

import org.forgerock.json.JsonValue;
import org.forgerock.oauth.OAuthException;
import org.forgerock.oauth.UserInfo;

/**
 * @author manip
 *
 */
public class MyInfoOAuthUserInfo implements UserInfo {
	private final JsonValue rawProfile;
	private final String subject;
	private final String authenticationIdKey;

	public MyInfoOAuthUserInfo(final String authenticationIdKey, final JsonValue rawProfile) {
		this.authenticationIdKey = authenticationIdKey;
		this.rawProfile = rawProfile;
		this.subject = rawProfile.get(authenticationIdKey).required().asString();
	}

	@Override
	public String getSubject() throws OAuthException {
		return subject;
	}

	@Override
	public JsonValue getRawProfile() throws OAuthException {
		return rawProfile;
	}

}
