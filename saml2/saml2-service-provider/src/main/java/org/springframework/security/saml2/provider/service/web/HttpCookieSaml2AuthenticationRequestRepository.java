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

package org.springframework.security.saml2.provider.service.web;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.time.Duration;
import java.util.Base64;
import java.util.Objects;
import java.util.stream.Stream;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;

/**
 * A {@link Saml2AuthenticationRequestRepository} implementation that uses {@link Cookie}
 * to store and retrieve the {@link AbstractSaml2AuthenticationRequest}
 *
 * @author Thomas Beckmann
 * @since 5.8
 */
public class HttpCookieSaml2AuthenticationRequestRepository
		implements Saml2AuthenticationRequestRepository<AbstractSaml2AuthenticationRequest> {

	@NonNull
	private final String cookieName;

	private final int cookieMaxAge;

	public HttpCookieSaml2AuthenticationRequestRepository(@NonNull final String cookieName,
			@Nullable final Duration cookieExpiry) {
		this.cookieName = Objects.requireNonNull(cookieName, "cookieName");
		this.cookieMaxAge = (cookieExpiry != null) ? (int) cookieExpiry.toSeconds() : -1;
	}

	@Override
	public AbstractSaml2AuthenticationRequest loadAuthenticationRequest(final HttpServletRequest request) {
		return Stream.ofNullable((request != null) ? request.getCookies() : null).flatMap(Stream::of)
				.filter((cookie) -> this.cookieName.equals(cookie.getName())).findFirst()
				.map((cookie) -> deserialize(cookie.getValue())).orElse(null);
	}

	@Override
	public void saveAuthenticationRequest(final AbstractSaml2AuthenticationRequest authenticationRequest,
			final HttpServletRequest request, final HttpServletResponse response) {
		if (response != null) {
			final var cookie = new Cookie(this.cookieName,
					(authenticationRequest != null) ? serialize(authenticationRequest) : null);
			cookie.setPath("/");
			cookie.setHttpOnly(true);
			cookie.setMaxAge((authenticationRequest != null) ? this.cookieMaxAge : 0);
			cookie.setSecure(request.isSecure());
			cookie.setHttpOnly(true);
			response.addCookie(cookie);
		}
	}

	@Override
	public AbstractSaml2AuthenticationRequest removeAuthenticationRequest(final HttpServletRequest request,
			final HttpServletResponse response) {
		final AbstractSaml2AuthenticationRequest authenticationRequest = loadAuthenticationRequest(request);
		saveAuthenticationRequest(null, request, response);
		return authenticationRequest;
	}

	@Nullable
	private String serialize(@Nullable final AbstractSaml2AuthenticationRequest authenticationRequest) {
		if (authenticationRequest == null) {
			return null;
		}
		final var baos = new ByteArrayOutputStream(4096);
		try (var os = new ObjectOutputStream(new GZIPOutputStream(baos, true))) {
			os.writeObject(authenticationRequest);
		}
		catch (final Exception ex) {
			throw new IllegalArgumentException(
					"Failed to serialize object of type: " + authenticationRequest.getClass(), ex);
		}
		final byte[] bytes = baos.toByteArray();
		return Base64.getUrlEncoder().encodeToString(bytes);
	}

	@Nullable
	private AbstractSaml2AuthenticationRequest deserialize(@Nullable final String serializedObj) {
		if (serializedObj == null) {
			return null;
		}
		final byte[] bytes = Base64.getUrlDecoder().decode(serializedObj);
		try (var is = new ObjectInputStream(new GZIPInputStream(new ByteArrayInputStream(bytes)))) {
			return (AbstractSaml2AuthenticationRequest) is.readObject();
		}
		catch (final Exception ex) {
			throw new IllegalArgumentException("Failed to deserialize object", ex);
		}
	}

}
