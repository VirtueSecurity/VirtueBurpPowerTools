package com.nickcoblentz.montoya

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ToolType
import burp.api.montoya.http.handler.*
import burp.api.montoya.http.message.HttpRequestResponse
import java.time.Instant

class ScannerMonitorHttpHandler(
    private val api: MontoyaApi,
    private val viewModel: SmartScanViewModel
) : HttpHandler {

    override fun handleHttpRequestToBeSent(requestToBeSent: HttpRequestToBeSent): RequestToBeSentAction {
        return RequestToBeSentAction.continueWith(requestToBeSent)
    }

    override fun handleHttpResponseReceived(responseReceived: HttpResponseReceived): ResponseReceivedAction {
        if (responseReceived.toolSource().isFromTool(ToolType.SCANNER)) {
            val response = (responseReceived as? HttpRequestResponse)?.response()
            val statusCode = response?.statusCode()?.toInt() ?: -1
            val timing = (responseReceived as? HttpRequestResponse)?.timingData()
            
            var durationMs = -1L
            timing?.ifPresent { t ->
                t.timeBetweenRequestSentAndEndOfResponse()?.let { d ->
                    durationMs = d.toMillis()
                }
            }
            
            viewModel.addScannerMetric(
                statusCode = statusCode,
                durationMs = durationMs,
                timestamp = Instant.now()
            )
        }
        return ResponseReceivedAction.continueWith(responseReceived)
    }
}
