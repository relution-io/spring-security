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

import java.time.Duration;

import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;

class HttpCookieOAuth2AuthorizationRequestRepositoryTests {

	private static final String COOKIE = "COOKIE";

	private final HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository = new HttpCookieOAuth2AuthorizationRequestRepository(
			COOKIE, Duration.ofSeconds(1000L));

	@Test
	void testCookie() {
		final var httpServletRequest = new MockHttpServletRequest();
		final var httpServletResponse = new MockHttpServletResponse();

		this.httpCookieOAuth2AuthorizationRequestRepository.saveAuthorizationRequest(
				OAuth2AuthorizationRequest.authorizationCode().clientId(getClass().getSimpleName())
						.authorizationUri("/auth").state("testCookie").build(),
				httpServletRequest, httpServletResponse);

		var cookie = httpServletResponse.getCookie(COOKIE);
		assertThat(cookie).as(COOKIE).isNotNull();
		assertThat(cookie.getName()).isEqualTo(COOKIE);
		assertThat(cookie.getPath()).isEqualTo("/");
		assertThat(cookie.getMaxAge()).isEqualTo(1000);
		assertThat(cookie.getValue()).isNotBlank().hasSizeLessThanOrEqualTo(4096);

		httpServletRequest.setCookies(cookie);
		httpServletResponse.reset();

		assertThat(this.httpCookieOAuth2AuthorizationRequestRepository.removeAuthorizationRequest(httpServletRequest,
				httpServletResponse)).isNotNull().satisfies((authorizationRequest) -> {
					assertThat(authorizationRequest.getClientId()).isEqualTo(getClass().getSimpleName());
					assertThat(authorizationRequest.getAuthorizationUri()).isEqualTo("/auth");
					assertThat(authorizationRequest.getState()).isEqualTo("testCookie");
				});

		cookie = httpServletResponse.getCookie(COOKIE);
		assertThat(cookie).as(COOKIE).isNotNull();
		assertThat(cookie.getName()).isEqualTo(COOKIE);
		assertThat(cookie.getPath()).isEqualTo("/");
		assertThat(cookie.getMaxAge()).isZero();
	}

	@Test
	void testLoadAuthorizationRequestNull() {
		assertThat(this.httpCookieOAuth2AuthorizationRequestRepository.loadAuthorizationRequest(null)).isNull();
	}

	@Test
	void testSaveAuthorizationRequestNulls() {
		assertThatNoException().isThrownBy(
				() -> this.httpCookieOAuth2AuthorizationRequestRepository.saveAuthorizationRequest(null, null, null));
	}

	@Test
	void testRemoveAuthorizationRequestNulls() {
		assertThat(this.httpCookieOAuth2AuthorizationRequestRepository.removeAuthorizationRequest(null, null)).isNull();
	}

}
