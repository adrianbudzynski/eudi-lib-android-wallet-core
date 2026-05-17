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

package eu.europa.ec.eudi.wallet.transfer.openId4vp

import eu.europa.ec.eudi.iso18013.transfer.TransferEvent
import eu.europa.ec.eudi.iso18013.transfer.response.RequestProcessor
import eu.europa.ec.eudi.wallet.transfer.openId4vp.dcql.ProcessedDcqlRequest

/**
 * Returns resolved OpenID4VP transaction data when [this] is a [ProcessedDcqlRequest].
 */
fun RequestProcessor.ProcessedRequest.Success.transactionDataOrNull(): List<TransactionData>? =
    when (this) {
        is ProcessedDcqlRequest -> transactionData
        else -> null
    }

/**
 * Returns resolved OpenID4VP transaction data from a [TransferEvent.RequestReceived] event.
 */
fun TransferEvent.RequestReceived.transactionDataOrNull(): List<TransactionData>? =
    (processedRequest as? RequestProcessor.ProcessedRequest.Success)?.transactionDataOrNull()

/**
 * Returns resolved OpenID4VP transaction data when [this] is an [OpenId4VpRequest].
 */
fun eu.europa.ec.eudi.iso18013.transfer.response.Request.openId4VpTransactionDataOrNull(): List<TransactionData>? =
    (this as? OpenId4VpRequest)?.resolvedRequestObject?.transactionData
