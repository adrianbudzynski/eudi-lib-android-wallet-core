/*
 * Copyright (c) 2023-2026 European Commission
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
 */

package eu.europa.ec.eudi.wallet.internal

import eu.europa.ec.eudi.openid4vp.ResponseMode
import org.junit.Test
import java.net.URI
import java.net.URL
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class ResponseModeKbJwtExtensionsTest {

    @Test
    fun `toKbJwtValue maps all response modes`() {
        val responseUri = URL("https://verifier.example/response")
        val redirectUri = URI("https://verifier.example/redirect")
        assertEquals("direct_post", ResponseMode.DirectPost(responseUri).toKbJwtValue())
        assertEquals("direct_post.jwt", ResponseMode.DirectPostJwt(responseUri).toKbJwtValue())
        assertEquals("fragment", ResponseMode.Fragment(redirectUri).toKbJwtValue())
        assertEquals("fragment.jwt", ResponseMode.FragmentJwt(redirectUri).toKbJwtValue())
        assertEquals("query", ResponseMode.Query(redirectUri).toKbJwtValue())
        assertEquals("query.jwt", ResponseMode.QueryJwt(redirectUri).toKbJwtValue())
    }
}

class ScaKbJwtClaimsTest {

    @Test
    fun `requires at least two amr categories`() {
        assertFailsWith<IllegalArgumentException> {
            ScaKbJwtClaims(
                jti = "id",
                responseMode = "direct_post",
                amr = listOf(mapOf("knowledge" to "pin_6_or_more_digits")),
            )
        }
    }

    @Test
    fun `accepts valid amr with two categories`() {
        val claims = ScaKbJwtClaims(
            jti = "deeec2b0-3bea-4477-bd5d-e3462a709481",
            responseMode = "direct_post",
            amr = listOf(
                mapOf("knowledge" to "pin_6_or_more_digits"),
                mapOf("possession" to "key_in_local_native_wscd"),
            ),
        )
        assertEquals("direct_post", claims.responseMode)
        assertEquals(2, claims.amr.size)
    }
}
