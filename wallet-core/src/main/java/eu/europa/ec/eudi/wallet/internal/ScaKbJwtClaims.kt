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
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * TS12-required Key Binding JWT claims for SCA attestation presentations.
 *
 * @see <a href="https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts12-electronic-payments-SCA-implementation-with-wallet.md">TS12 §3.6</a>
 */
internal data class ScaKbJwtClaims(
    val jti: String,
    val responseMode: String,
    val amr: List<Map<String, String>>,
) {
    init {
        require(jti.isNotBlank()) { "jti must not be blank" }
        require(responseMode.isNotBlank()) { "response_mode must not be blank" }
        require(amr.size >= 2) { "amr must contain at least two authentication categories" }
        amr.forEach { entry ->
            require(entry.size == 1) { "Each amr entry must have exactly one category key" }
        }
    }

    fun toKeyBindingClaims(): Map<String, JsonElement> = mapOf(
        CLAIM_JTI to JsonPrimitive(jti),
        CLAIM_RESPONSE_MODE to JsonPrimitive(responseMode),
        CLAIM_AMR to JsonArray(
            amr.map { entry ->
                JsonObject(entry.mapValues { (_, value) -> JsonPrimitive(value) })
            }
        ),
    )

    companion object {
        const val CLAIM_JTI: String = "jti"
        const val CLAIM_RESPONSE_MODE: String = "response_mode"
        const val CLAIM_AMR: String = "amr"
    }
}

/**
 * Maps [ResponseMode] to the OID4VP `response_mode` parameter value for the KB-JWT `response_mode` claim.
 */
internal fun ResponseMode.toKbJwtValue(): String =
    when (this) {
        is ResponseMode.DirectPost -> "direct_post"
        is ResponseMode.DirectPostJwt -> "direct_post.jwt"
        is ResponseMode.Fragment -> "fragment"
        is ResponseMode.FragmentJwt -> "fragment.jwt"
        is ResponseMode.Query -> "query"
        is ResponseMode.QueryJwt -> "query.jwt"
        is ResponseMode.DCApi -> "dc_api"
        is ResponseMode.DCApiJwt -> "dc_api.jwt"
    }
