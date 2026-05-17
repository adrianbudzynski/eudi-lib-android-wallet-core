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

import eu.europa.ec.eudi.openid4vp.HashAlgorithm
import eu.europa.ec.eudi.openid4vp.TransactionData
import eu.europa.ec.eudi.openid4vp.TransactionDataType
import eu.europa.ec.eudi.openid4vp.dcql.QueryId
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Test
import java.security.MessageDigest
import java.util.Base64
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull

class TransactionDataHashingTest {

    @Test
    fun `hashTransactionData uses sha-256 over base64url string without decoding`() {
        val payloadJson = """{"transaction_id":"tx-1","action":"login"}"""
        val encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadJson.toByteArray())

        val expectedDigest = MessageDigest.getInstance("SHA-256")
            .digest(encoded.toByteArray(Charsets.UTF_8))
        val expected = Base64.getUrlEncoder().withoutPadding().encodeToString(expectedDigest)

        val actual = TransactionDataHashing.hashTransactionData(encoded, HashAlgorithm.SHA_256)
        assertEquals(expected, actual)

        val hashOverDecodedPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(
            MessageDigest.getInstance("SHA-256").digest(payloadJson.toByteArray()),
        )
        assertNotEquals(hashOverDecodedPayload, actual)
    }

    @Test
    fun `kbJwtTransactionDataClaims returns hashes and algorithm`() {
        val transactionData = TransactionData.sdJwtVc(
            type = TransactionDataType("urn:eudi:sca:login_risk_transaction:1"),
            credentialIds = listOf(QueryId("sca_cred")),
            hashAlgorithms = listOf(HashAlgorithm.SHA_256),
        ) {
            put("payload", buildJsonObject {
                put("transaction_id", "tx-1")
                put("action", "login")
            })
        }

        val claims = TransactionDataHashing.kbJwtTransactionDataClaims(listOf(transactionData))
        assertNotNull(claims)
        val (hashes, alg) = claims
        assertEquals("sha-256", alg)
        assertEquals(1, hashes.size)
        assertEquals(
            TransactionDataHashing.hashTransactionData(transactionData.value, HashAlgorithm.SHA_256),
            hashes.single(),
        )
    }

    @Test
    fun `hashTransactionData matches Signicat login risk transaction shape`() {
        val transactionData = TransactionData.sdJwtVc(
            type = TransactionDataType("urn:eudi:sca:login_risk_transaction:1"),
            credentialIds = listOf(QueryId("sca_user")),
            hashAlgorithms = listOf(HashAlgorithm.SHA_256),
        ) {
            put("payload", buildJsonObject {
                put("transaction_id", "8d8ac610-566d-4ef0-9c22-186b2a5ed793")
                put("action", "Login to Sample Bank")
                put("service", "Sample Bank Online")
                put("date_time", "2026-05-13T10:15:00Z")
            })
        }

        val expected = Base64.getUrlEncoder().withoutPadding().encodeToString(
            MessageDigest.getInstance("SHA-256")
                .digest(transactionData.value.toByteArray(Charsets.UTF_8)),
        )
        val actual = TransactionDataHashing.hashTransactionData(
            transactionData.value,
            HashAlgorithm.SHA_256,
        )
        assertEquals(expected, actual)
    }
}
