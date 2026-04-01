package com.nickcoblentz.montoya

import MyExtensionSettings
import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.ui.contextmenu.AuditIssueContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider
import burp.api.montoya.ui.contextmenu.WebSocketContextMenuEvent
import java.awt.Component
import java.awt.Font
import javax.swing.JLabel
import javax.swing.JMenuItem
import javax.swing.JSeparator

class HTTPPromptContext(private val prompt : String = "The prompt goes here...",
    private val httpRequest : HttpRequest,
    private val httpResponse : HttpResponse?=null,
    private val selectedText : String,
    private val redact : Boolean = true) {

    private val regexOptions =  setOf(RegexOption.IGNORE_CASE, RegexOption.MULTILINE)

    private fun redact(targetHttpRequest: HttpRequest) : String {
        return redactHost(redactAuthorizationHeader(httpRequest.toString()))
    }

    private fun redact(targetHttpResponse: HttpResponse) : String {
        return redactHost(redactAuthorizationHeader(httpRequest.toString()))
    }

    private fun redactHost(targetHttpRequest: String) : String {
        return targetHttpRequest.replace(httpRequest.httpService().host(),"example.localhost.com")
    }

    private fun redactAuthorizationHeader(targetHttpRequest: String) : String {
        if(httpRequest.hasHeader("Authorization")) {
            val authorizationHeader = httpRequest.header("Authorization")
            if(authorizationHeader.value().startsWith("Bearer ")) {
                return targetHttpRequest.replace("Authorization: Bearer .*?$".toRegex(regexOptions),"Authorization: Bearer REDACTED")
            }
            else {
                return targetHttpRequest.replace("Authorization: .*?$".toRegex(regexOptions),"Authorization: REDACTED")
            }
        }

        return targetHttpRequest
    }



    fun getPromptContext() {
        buildString {
            append("$prompt\n\n")
            if(selectedText.isNotBlank()) {
                append("The parameter `$selectedText`.")

            }
            appendLine("HTTP Request:")
            appendLine("""```""")
            appendLine(redact(httpRequest))
            appendLine("""```""")

            httpResponse?.let { httpResponse ->
                appendLine("HTTP Response:")
                appendLine("""```""")
                appendLine(redact(httpResponse))
                appendLine("""```""")
            }
        }
    }

}

data class WSMessagePromptContext(val url : String, val message : String, val host : String, val redact : Boolean = true) {

}

class AIUtils(private val api: MontoyaApi, private val myExtensionSettings : MyExtensionSettings) : ContextMenuItemsProvider {
    private val logger: MontoyaLogger = MontoyaLogger(api, LogLevel.DEBUG)
    private val pluginName = "AI Utils"

    private val label = JLabel("  AI Utils").apply {
        isEnabled = false
        font = font.deriveFont(Font.BOLD)
    }

    private val copyAsAIPromptMenuItem = JMenuItem("Copy As AI Prompt")

    private val menuItems : MutableList<Component> = mutableListOf(label,copyAsAIPromptMenuItem,JSeparator())

    private var currentHttpRequest : HttpRequest? = null
    private var currentHttpResponse : HttpResponse? = null

    init {


        logger.debugLog("Started loading the $pluginName extension...")

        api.extension().registerUnloadingHandler {
            logger.debugLog("Unloading the $pluginName extension...")

        }

        api.userInterface().registerContextMenuItemsProvider(this)

        copyAsAIPromptMenuItem.addActionListener { _ -> copyAsAIPrompt() }

        logger.debugLog("Finished loading the $pluginName extension...")
    }

    private fun copyAsAIPrompt() {
        TODO("Not yet implemented")
    }

    override fun provideMenuItems(event: ContextMenuEvent): MutableList<Component> {
        resetRequestResponse()
        val found = if(event.messageEditorRequestResponse().isPresent) {
            val httpRequestResponse  = event.messageEditorRequestResponse().get()
            currentHttpRequest = httpRequestResponse.requestResponse().request()
            currentHttpResponse = httpRequestResponse.requestResponse().response()
            true
        }
        else if(event.selectedRequestResponses().count()==1) {
            currentHttpRequest = event.selectedRequestResponses()[0].request()
            currentHttpResponse = event.selectedRequestResponses()[0].response()
            true
        } else {
            false
        }
        return mutableListOf<Component>()
    }

    override fun provideMenuItems(event: WebSocketContextMenuEvent): MutableList<Component> {
        resetRequestResponse()
        return mutableListOf<Component>()
    }

    override fun provideMenuItems(event: AuditIssueContextMenuEvent): MutableList<Component> {
        resetRequestResponse()
        return mutableListOf<Component>()
    }

    private fun resetRequestResponse() {
        currentHttpRequest=null
        currentHttpResponse=null
    }


}