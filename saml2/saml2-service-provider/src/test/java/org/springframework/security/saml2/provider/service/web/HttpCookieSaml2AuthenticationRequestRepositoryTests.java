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

import java.time.Duration;

import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.saml2.provider.service.authentication.Saml2RedirectAuthenticationRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;

class HttpCookieSaml2AuthenticationRequestRepositoryTests {

	private static final String COOKIE = "COOKIE";

	private final HttpCookieSaml2AuthenticationRequestRepository httpCookieSaml2AuthenticationRequestRepository = new HttpCookieSaml2AuthenticationRequestRepository(
			COOKIE, Duration.ofSeconds(1000L));

	@Test
	void testCookie() {
		final var httpServletRequest = new MockHttpServletRequest();
		final var httpServletResponse = new MockHttpServletResponse();

		this.httpCookieSaml2AuthenticationRequestRepository.saveAuthenticationRequest(Saml2RedirectAuthenticationRequest
				.withRelyingPartyRegistration(RelyingPartyRegistration.withRegistrationId("registrationId")
						.entityId("entityId")
						.assertingPartyDetails((assertingPartyDetails) -> assertingPartyDetails.entityId("entityId")
								.singleSignOnServiceLocation("singleSignOnServiceLocation"))
						.build())
				.samlRequest("samlRequest").relayState("relayState").build(), httpServletRequest, httpServletResponse);

		var cookie = httpServletResponse.getCookie(COOKIE);
		assertThat(cookie).as(COOKIE).isNotNull();
		assertThat(cookie.getName()).isEqualTo(COOKIE);
		assertThat(cookie.getPath()).isEqualTo("/");
		assertThat(cookie.getMaxAge()).isEqualTo(1000);
		assertThat(cookie.getValue()).isNotBlank().hasSizeLessThanOrEqualTo(4096);

		httpServletRequest.setCookies(cookie);
		httpServletResponse.reset();

		assertThat(this.httpCookieSaml2AuthenticationRequestRepository.removeAuthenticationRequest(httpServletRequest,
				httpServletResponse)).isNotNull().satisfies((authorizationRequest) -> {
					assertThat(authorizationRequest.getRelayState()).isEqualTo("relayState");
					assertThat(authorizationRequest.getSamlRequest()).isEqualTo("samlRequest");
				});

		cookie = httpServletResponse.getCookie(COOKIE);
		assertThat(cookie).as(COOKIE).isNotNull();
		assertThat(cookie.getName()).isEqualTo(COOKIE);
		assertThat(cookie.getPath()).isEqualTo("/");
		assertThat(cookie.getMaxAge()).isZero();
	}

	@Test
	void testLoadAuthorizationRequestNull() {
		assertThat(this.httpCookieSaml2AuthenticationRequestRepository.loadAuthenticationRequest(null)).isNull();
	}

	@Test
	void testSaveAuthorizationRequestNulls() {
		assertThatNoException().isThrownBy(
				() -> this.httpCookieSaml2AuthenticationRequestRepository.saveAuthenticationRequest(null, null, null));
	}

	@Test
	void testRemoveAuthorizationRequestNulls() {
		assertThat(this.httpCookieSaml2AuthenticationRequestRepository.removeAuthenticationRequest(null, null))
				.isNull();
	}

}
