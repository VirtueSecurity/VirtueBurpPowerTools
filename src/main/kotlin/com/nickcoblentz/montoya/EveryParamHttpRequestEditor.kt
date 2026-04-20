package com.nickcoblentz.montoya

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.ui.Selection
import burp.api.montoya.ui.editor.EditorOptions
import burp.api.montoya.ui.editor.HttpRequestEditor
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor
import com.nickcoblentz.montoya.EveryParameter2.Companion.BAMBDA_CATEGORY
import java.awt.Component
import java.util.Optional
import kotlin.jvm.optionals.getOrNull

class EveryParamHttpRequestEditor(private val api: MontoyaApi) : ExtensionProvidedHttpRequestEditor {
    val logger = MontoyaLogger(api, LogLevel.DEBUG)

    var _requestResponse: HttpRequestResponse? = null

    val editor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY, EditorOptions.WRAP_LINES)

    override fun getRequest(): HttpRequest? {
        return _requestResponse?.request()
    }

    override fun setRequestResponse(requestResponse: HttpRequestResponse?) {
        requestResponse?.let { reqRes ->
            _requestResponse = reqRes
            val requestString = reqRes.request().toString()
            val decodedRequest = EveryParameter2.allTestCaseHeaders.fold(reqRes.request()) { req, item ->
                if (requestString.contains(item, ignoreCase = true)) {
                    val encodedValue = req.headerValue(item)
                    if(encodedValue != null) {
                        req.withUpdatedHeader(item, api.utilities().base64Utils().decode(encodedValue).toString())
                    }
                    else {
                        req
                    }
                } else {
                    req
                }
            }
            editor.request=decodedRequest
            editor.setCaretPosition(decodedRequest.toString().lastIndexOf("Z-Test-Case-"))
        }
    }

    override fun isEnabledFor(requestResponse: HttpRequestResponse?): Boolean {
        val requestString = requestResponse?.request()?.toString() ?: return false
        return EveryParameter2.allTestCaseHeaders.any { requestString.contains(it, ignoreCase = true) }
    }


    override fun caption(): String? = "Every Param"


    override fun isModified(): Boolean = editor.isModified;

    override fun uiComponent(): Component? = editor.uiComponent()

    override fun selectedData(): Selection? = editor.selection().getOrNull()
}