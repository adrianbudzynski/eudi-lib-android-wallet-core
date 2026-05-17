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
import eu.europa.ec.eudi.openid4vp.SupportedTransactionDataType
import eu.europa.ec.eudi.openid4vp.TransactionDataType
import eu.europa.ec.eudi.wallet.transfer.openId4vp.ClientIdScheme
import eu.europa.ec.eudi.wallet.transfer.openId4vp.Format
import eu.europa.ec.eudi.wallet.transfer.openId4vp.OpenId4VpConfig
import eu.europa.ec.eudi.wallet.transfer.openId4vp.OpenId4VpReaderTrustImpl
import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class OpenId4VpConfigMappingTest {

    @Test
    fun `makeOpenId4VPConfig passes supportedTransactionDataTypes to VPConfiguration`() {
        val loginRiskType = SupportedTransactionDataType.SdJwtVc(
            type = TransactionDataType("urn:eudi:sca:login_risk_transaction:1"),
            hashAlgorithms = setOf(HashAlgorithm.SHA_256),
        )
        val config = OpenId4VpConfig.Builder()
            .withClientIdSchemes(ClientIdScheme.RedirectUri)
            .withFormats(Format.SdJwtVc.ES256)
            .withSupportedTransactionDataTypes(loginRiskType)
            .build()

        val openId4VpConfig = makeOpenId4VPConfig(config, OpenId4VpReaderTrustImpl(null))

        assertEquals(1, openId4VpConfig.vpConfiguration.supportedTransactionDataTypes.size)
        val mapped = openId4VpConfig.vpConfiguration.supportedTransactionDataTypes.single()
        assertIs<SupportedTransactionDataType.SdJwtVc>(mapped)
        assertEquals(loginRiskType.type, mapped.type)
        assertEquals(loginRiskType.hashAlgorithms, mapped.hashAlgorithms)
    }
}
