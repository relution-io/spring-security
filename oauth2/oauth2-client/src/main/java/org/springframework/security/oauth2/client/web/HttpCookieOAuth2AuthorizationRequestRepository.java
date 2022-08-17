/*
 * Copyright 2002-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.client.web;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.Duration;
import java.util.Base64;
import java.util.stream.Stream;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.security.jackson2.CoreJackson2Module;
import org.springframework.security.oauth2.client.jackson2.OAuth2ClientJackson2Module;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

/**
 * An implementation of an {@link AuthorizationRequestRepository} that stores
 * {@link OAuth2AuthorizationRequest} in a {@code Cookie}.
 *
 * @author Thomas Beckmann
 * @since 5.8
 */
public class HttpCookieOAuth2AuthorizationRequestRepository
		implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {

	@NonNull
	private final String cookieName;

	@NonNull
	private final int cookieMaxAge;

	@NonNull
	private final ObjectMapper objectMapper;

	public HttpCookieOAuth2AuthorizationRequestRepository(@NonNull final String cookieName,
			@Nullable final Duration cookieExpiry) {
		this.cookieName = cookieName;
		this.cookieMaxAge = (cookieExpiry != null) ? (int) cookieExpiry.toSeconds() : -1;
		this.objectMapper = new ObjectMapper().registerModules(new CoreJackson2Module(),
				new OAuth2ClientJackson2Module());
	}

	/**
	 * Loads the OAuth2 authorization request for a matching cookie, which does not
	 * contain a JWT Token.
	 * @param request that can contain the cookie from which the OAuth2 authorization
	 * request can be created
	 * @return {@link OAuth2AuthorizationRequest} created from the request cookie or null,
	 * if the needed cookie is not contained in the request or the cookie already contains
	 * a JWT token
	 */
	@Override
	@Nullable
	public OAuth2AuthorizationRequest loadAuthorizationRequest(@Nullable final HttpServletRequest request) {
		return Stream.ofNullable((request != null) ? request.getCookies() : null).flatMap(Stream::of)
				.filter((cookie) -> this.cookieName.equals(cookie.getName())).findFirst()
				.map((cookie) -> deserialize(cookie.getValue())).orElse(null);
	}

	@Override
	public void saveAuthorizationRequest(final OAuth2AuthorizationRequest authorizationRequest,
			final HttpServletRequest request, final HttpServletResponse response) {
		if (response != null) {
			final var cookie = new Cookie(this.cookieName,
					(authorizationRequest != null) ? serialize(authorizationRequest) : null);
			cookie.setPath("/");
			cookie.setHttpOnly(true);
			cookie.setMaxAge((authorizationRequest != null) ? this.cookieMaxAge : 0);
			cookie.setSecure(true);
			cookie.setHttpOnly(true);
			response.addCookie(cookie);
		}
	}

	@Override
	public OAuth2AuthorizationRequest removeAuthorizationRequest(final HttpServletRequest request,
			final HttpServletResponse response) {
		final OAuth2AuthorizationRequest authorizationRequest = loadAuthorizationRequest(request);
		saveAuthorizationRequest(null, request, response);
		return authorizationRequest;
	}

	@Nullable
	private String serialize(@Nullable final OAuth2AuthorizationRequest oAuth2AuthorizationRequest) {
		if (oAuth2AuthorizationRequest == null) {
			return null;
		}
		final var baos = new ByteArrayOutputStream(4096);
		try (var os = new GZIPOutputStream(baos, true)) {
			this.objectMapper.writeValue(os, oAuth2AuthorizationRequest);
		}
		catch (final IOException ex) {
			throw new IllegalArgumentException(
					"Failed to serialize object of type: " + oAuth2AuthorizationRequest.getClass(), ex);
		}
		final byte[] bytes = baos.toByteArray();
		return Base64.getUrlEncoder().encodeToString(bytes);
	}

	@Nullable
	private OAuth2AuthorizationRequest deserialize(@Nullable final String serializedObj) {
		if (serializedObj == null) {
			return null;
		}
		final byte[] bytes = Base64.getUrlDecoder().decode(serializedObj);
		try (var is = new GZIPInputStream(new ByteArrayInputStream(bytes))) {
			return this.objectMapper.readValue(is, OAuth2AuthorizationRequest.class);
		}
		catch (final IOException ex) {
			throw new IllegalArgumentException("Failed to deserialize object", ex);
		}
	}

}
