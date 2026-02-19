package com.nickcoblentz.montoya.utils

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray
import burp.api.montoya.http.message.ContentType
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.ui.contextmenu.*
import burp.api.montoya.utilities.json.JsonNode
import com.nickcoblentz.montoya.LogLevel
import com.nickcoblentz.montoya.MontoyaLogger
import java.awt.Toolkit
import java.awt.datatransfer.Clipboard
import java.awt.datatransfer.ClipboardOwner
import java.awt.datatransfer.StringSelection
import java.awt.datatransfer.Transferable
import java.nio.ByteBuffer
import java.nio.charset.CharsetDecoder
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets


class CopyRequestResponseHandler (private val _api: MontoyaApi) : ClipboardOwner {

    private val _requestHeadersToStrip: Set<String> = setOf<String>(
        "Sec-Ch-Ua",
        "Sec-Ch-Ua-Mobile",
        "Sec-Ch-Ua-Full-Version",
        "Sec-Ch-Ua-Arch",
        "Sec-Ch-Ua-Platform",
        "Sec-Ch-Ua-Platform-Version",
        "Sec-Ch-Ua-Model",
        "Sec-Ch-Ua-Bitness",
        "Sec-Ch-Ua-Wow64",
        "Sec-Ch-Ua-Full-Version-List",
        "Upgrade-Insecure-Requests",
        "Sec-Fetch-Site",
        "Sec-Fetch-Mode",
        "Sec-Fetch-User",
        "Sec-Fetch-Dest",
        "Accept-Language",
        "Accept-Encoding",
        "Accept",
        "Priority"
    )

    private val _responseHeadersToStrip: Set<String> = setOf<String>(
        "Accept-Ch",
        "P3p",
        "Cache-Control",
        "Pragma",
        "Expires",
        "X-Frame-Options",
        "X-Robots-Tag",
        "X-XSS-Protection",
        "X-Content-Type-Options",
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "Last-Modified",
        "Vary",
        "X-Ua-Compatible",
        "Report-To",
        "Nel",
        "Reporting-Endpoints",
        "Etag"
    )

    enum class CopyMode {
        RequestFullResponseFull,
        RequestFullResponseHeaders,
        URLResponseFull,
        URLResponseHeaders,
        ResponseBody
    }

    var logger: MontoyaLogger = MontoyaLogger(_api, LogLevel.DEBUG)

    override fun lostOwnership(clipboard: Clipboard, contents: Transferable) {
    }

    fun copyItem(wsMessage : WebSocketMessage, stripHeaders: Boolean = true, copyMode : CopyMode=CopyMode.RequestFullResponseFull, prettifyJSON: Boolean = true) : String =
            CopyBuilder()
                .withUrlWS(wsMessage.upgradeRequest().url(),wsMessage.direction().toString())
                .withWS(prettifyJSONBody(wsMessage,prettifyJSON)).toString()


    fun prettifyJSONBody(wsMessage : WebSocketMessage, shouldPrettify : Boolean) : String
    {
        if(shouldPrettify) {
            val wsPayloadString = convertWSPayloadToString(wsMessage.payload())
            wsPayloadString?.let { payload ->
                if(_api.utilities().jsonUtils().isValidJson(payload)) {
                    return JsonNode.jsonNode(payload).toJsonString()
                }
            }
        }

        return wsMessage.payload().toString()
    }

    fun convertWSPayloadToString(payload: ByteArray): String? {

        val bytes = payload.bytes

        // 2. Fast-fail for common binary indicators (Null bytes)
        // Standard JSON/JS strings in WebSockets rarely contain null terminators.
        if (bytes.any { it == 0.toByte() }) return null

        // 3. Strict UTF-8 Validation
        return try {
            val decoder = StandardCharsets.UTF_8.newDecoder().apply {
                onMalformedInput(CodingErrorAction.REPORT)
                onUnmappableCharacter(CodingErrorAction.REPORT)
            }

            val buffer = ByteBuffer.wrap(bytes)
            decoder.decode(buffer).toString()
        } catch (e: CharacterCodingException) {
            // If the decoder hits an invalid byte sequence, it's binary data
            null
        }
    }

    fun copyItemsWS(wsMessages : MutableList<WebSocketMessage>, stripHeaders: Boolean = true, copyMode : CopyMode=CopyMode.RequestFullResponseFull, prettifyJSON: Boolean = true) : String {
        if(wsMessages.isNotEmpty()) {

            return (wsMessages.map { wsMessage ->
                copyItem(wsMessage,stripHeaders,copyMode,prettifyJSON)
            }).joinToString("")
        }
        return ""
    }


    fun prettifyJSONBody(httpRequest : HttpRequest, shouldPrettify : Boolean) : String
    {
        if(shouldPrettify && httpRequest.hasHeader("Content-Type")) {
            val contentType = httpRequest.headerValue("Content-Type")
            val body = httpRequest.bodyToString()
            if(body.isNotBlank() && ( httpRequest.contentType() == ContentType.JSON ||
                contentType.contains("+json") ||
                contentType.contains("/json") ||
                contentType.contains("/javascript")) &&
                _api.utilities().jsonUtils().isValidJson(body)) {

                val prettyBody = JsonNode.jsonNode(body).toJsonString()
                val headers = httpRequest.toString().substring(0,httpRequest.bodyOffset())
                return headers + prettyBody
            }
        }

        return httpRequest.toString()
    }

    fun prettifyJSONBody(httpResponse : HttpResponse, shouldPrettify : Boolean) : String
    {
        if(shouldPrettify && httpResponse.hasHeader("Content-Type")) {
            val contentType = httpResponse.headerValue("Content-Type")
            val body = httpResponse.bodyToString()
            if(body.isNotBlank() && (contentType.contains("+json") ||
                        contentType.contains("/json") ||
                        contentType.contains("/javascript")) &&
                _api.utilities().jsonUtils().isValidJson(body)) {

                val prettyBody = JsonNode.jsonNode(body).toJsonString()
                val headers = httpResponse.toString().substring(0,httpResponse.bodyOffset())
                return headers + prettyBody
            }
        }

        return httpResponse.toString()
    }

    fun copyItem(requestResponse : HttpRequestResponse, stripHeaders: Boolean = true, copyMode : CopyMode=CopyMode.RequestFullResponseFull,prettifyJSON: Boolean = true) : String {
        return (
            CopyBuilder().apply {
                if(copyMode!= CopyMode.ResponseBody)
                    withUrlHTTP(requestResponse.request().url())
                if(copyMode!= CopyMode.ResponseBody && copyMode!= CopyMode.URLResponseFull && copyMode != CopyMode.URLResponseHeaders) {
                    val request =
                        if (stripHeaders) stripHeaders(requestResponse.request()) else requestResponse.request()

                    withHTTP(prettifyJSONBody(request,prettifyJSON))
                }

                if(requestResponse.hasResponse()) {
                    val response = if (stripHeaders) stripHeaders(requestResponse.response()) else requestResponse.response()
                    if(copyMode == CopyMode.ResponseBody)
                        withHTTP(response.bodyToString())
                    else if(copyMode == CopyMode.URLResponseHeaders || copyMode == CopyMode.RequestFullResponseHeaders)
                        withHTTP(response.toString().substring(0,response.bodyOffset()))
                    else
                        withHTTP(prettifyJSONBody(response,prettifyJSON))
                }
            }.toString())
    }

    fun copyItemsHTTP(requestResponses : MutableList<HttpRequestResponse>, stripHeaders: Boolean = true, copyMode : CopyMode=CopyMode.RequestFullResponseFull, prettifyJSON: Boolean = true) : String {
        if(requestResponses.isNotEmpty()) {

            return (requestResponses.map { requestResponse ->
                copyItem(requestResponse,stripHeaders,copyMode,prettifyJSON)
            }).joinToString("")
        }

        return ""
    }


    private fun stripHeaders(request : HttpRequest) : HttpRequest {
        var modifiedRequest = request
        for (headerName in _requestHeadersToStrip) {
            if(modifiedRequest.hasHeader(headerName)) {
                modifiedRequest = modifiedRequest.withRemovedHeader(headerName)
            }
        }
        return modifiedRequest
    }

    private fun stripHeaders(response : HttpResponse) : HttpResponse {
        var modifiedResponse = response
        for (headerName in _responseHeadersToStrip) {
            if(modifiedResponse.hasHeader(headerName)) {
                modifiedResponse = modifiedResponse.withRemovedHeader(headerName)
            }
        }
        return modifiedResponse
    }

    fun copyToClipboard(copyMe : String)
    {
        val clipboard = Toolkit.getDefaultToolkit().systemClipboard
        val transferable: Transferable = StringSelection(copyMe)
        clipboard.setContents(transferable, this)
    }

}