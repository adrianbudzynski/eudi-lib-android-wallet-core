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
import eu.europa.ec.eudi.openid4vp.OpenId4VPSpec
import eu.europa.ec.eudi.openid4vp.TransactionData
import java.security.MessageDigest
import java.util.Base64

/**
 * Computes OpenID4VP transaction-data digests for KB-JWT dynamic linking.
 *
 * @see <a href="https://github.com/openid/OpenID4VP/issues/457">OpenID4VP #457</a>
 */
internal object TransactionDataHashing {
    const val CLAIM_TRANSACTION_DATA_HASHES: String = "transaction_data_hashes"

    /**
     * Builds KB-JWT `transaction_data_hashes` and `transaction_data_hashes_alg` claim values.
     *
     * @return pair of hashes and algorithm name, or `null` when [transactionData] is empty
     */
    fun kbJwtTransactionDataClaims(
        transactionData: List<TransactionData>,
    ): Pair<List<String>, String>? {
        if (transactionData.isEmpty()) return null

        val sdJwtVcEntries = transactionData.filterIsInstance<TransactionData.SdJwtVc>()
        require(sdJwtVcEntries.size == transactionData.size) {
            "Only SD-JWT VC transaction data is supported for KB-JWT hashing"
        }

        val algorithms = sdJwtVcEntries.map { entry ->
            entry.hashAlgorithmsOrDefault.single()
        }
        require(algorithms.distinct().size == 1) {
            "Mixed transaction data hash algorithms are not supported in a single KB-JWT"
        }

        val algorithm = algorithms.first()
        val hashes = sdJwtVcEntries.map { hashTransactionData(it.value, algorithm) }
        return hashes to algorithm.name
    }

    /**
     * Hashes a single base64url-encoded [transactionDataValue] using [algorithm].
     * The digest is returned base64url-encoded without padding.
     */
    fun hashTransactionData(transactionDataValue: String, algorithm: HashAlgorithm): String {
        val digestAlgorithm = when (algorithm) {
            HashAlgorithm.SHA_256 -> "SHA-256"
            else -> throw IllegalArgumentException("Unsupported hash algorithm: ${algorithm.name}")
        }
        val decoded = Base64.getUrlDecoder().decode(transactionDataValue)
        val digest = MessageDigest.getInstance(digestAlgorithm).digest(decoded)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
    }

    val CLAIM_TRANSACTION_DATA_HASHES_ALG: String
        get() = OpenId4VPSpec.TRANSACTION_DATA_HASH_ALGORITHMS
}
