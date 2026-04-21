package com.nickcoblentz.montoya

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ToolType
import burp.api.montoya.http.handler.*
import java.time.Instant

class ScannerMonitorHttpHandler(
    private val api: MontoyaApi,
    private val viewModel: SmartScanViewModel
) : HttpHandler {

    override fun handleHttpRequestToBeSent(requestToBeSent: HttpRequestToBeSent): RequestToBeSentAction {
        if (requestToBeSent.toolSource().isFromTool(ToolType.SCANNER)) {
            viewModel.addScannerMetric(
                messageId = requestToBeSent.messageId(),
                type = ScannerMetricType.SENT,
                statusCode = 0,
                timestamp = Instant.now()
            )
        }
        return RequestToBeSentAction.continueWith(requestToBeSent)
    }

    override fun handleHttpResponseReceived(responseReceived: HttpResponseReceived): ResponseReceivedAction {
        if (responseReceived.toolSource().isFromTool(ToolType.SCANNER)) {
            val statusCode = responseReceived.statusCode().toInt() ?: -1
            
            viewModel.addScannerMetric(
                messageId = responseReceived.messageId(),
                type = ScannerMetricType.RECEIVED,
                statusCode = statusCode,
                timestamp = Instant.now()
            )
        }
        return ResponseReceivedAction.continueWith(responseReceived)
    }
}
