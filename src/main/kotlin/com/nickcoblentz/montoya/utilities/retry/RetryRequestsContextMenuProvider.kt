package com.nickcoblentz.montoya.utilities

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.proxy.websocket.ProxyWebSocketCreation
import burp.api.montoya.ui.contextmenu.AuditIssueContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider
import burp.api.montoya.ui.contextmenu.WebSocketContextMenuEvent
import burp.api.montoya.ui.contextmenu.WebSocketMessage
import burp.api.montoya.ui.hotkey.HotKey
import burp.api.montoya.ui.hotkey.HotKeyEvent
import java.awt.Component
import java.awt.Font
import java.awt.Toolkit
import java.awt.datatransfer.DataFlavor
import java.net.URI
import javax.swing.JLabel
import javax.swing.JMenuItem
import javax.swing.JSeparator

class RetryRequestsContextMenuProvider(
    private val api: MontoyaApi, //private List<ProxyWebSocketCreation> proxyWebSockets;
    private val myExecutor: MyExecutor,
    private val proxyWebSockets: MutableList<ProxyWebSocketCreation>
) : ContextMenuItemsProvider/*, HotKeyHandler*/ {

    companion object {
        const val RETRY_REQUESTS: String = "RetryRequests"
        const val RETRY_VERBS: String = "RetryVerbs"
        const val RETRY_VERBS_CONTENT_LENGTH: String = "RetryVerbsWContentLength"
        const val RETRY_VERBS_CONTENT_LENGTH_JSON: String = "RetryVerbsWContentLengthJson"
        const val RETRY_WS: String = "Retry WS"
        const val REQUEST_URLS_FROM_CLIPBOARD = "Request URLs from Clipboard"
    }

    private val _Verbs = listOf(
        "OPTIONS",
        "POST",
        "PUT",
        "PATCH",
        "HEAD",
        "GET",
        "TRACE",
        "TRACK",
        "LOCK",
        "UNLOCK",
        "FAKE",
        "CONNECT",
        "COPY",
        "MOVE",
        "LABEL",
        "UPDATE",
        "VERSION-CONTROL",
        "UNCHECKOUT",
        "CHECKOUT",
        "DELETE"
    )
    private val _VerbsNoBody = listOf("GET", "OPTIONS", "HEAD", "CONNECT", "TRACE")
    private val _MenuItemList: MutableList<Component>
    private val _RetryRequestJMenu = JMenuItem(RETRY_REQUESTS)
    private val _RetryVerbsJMenu = JMenuItem(RETRY_VERBS)
    private val _RetryVerbsCLJMenu = JMenuItem(RETRY_VERBS_CONTENT_LENGTH)
    private val _RetryVerbsCLJSONJMenu = JMenuItem(RETRY_VERBS_CONTENT_LENGTH_JSON)
    private val _RetryWSJMenu = JMenuItem(RETRY_WS)
    private val _RequestURLsFromClipboard = JMenuItem(REQUEST_URLS_FROM_CLIPBOARD)
    private var _Event: ContextMenuEvent? = null
    private var _WSEvent : WebSocketContextMenuEvent? = null
    private val _ListOpenWSJMenu = JMenuItem("List Open WS Connections")
    // Holds the most recently extracted URLs from the system clipboard
    private var _clipboardRequestUrls: List<String> = emptyList()

    init {
        // Use lambdas for distinct action handlers per menu item
        _RetryRequestJMenu.addActionListener { retrySelectedRequests(requestResponsesFromEvent(_Event)) }
        _RetryVerbsJMenu.addActionListener { retryVerbs(requestResponsesFromEvent(_Event),contentLength = false, json = false) }
        _RetryVerbsCLJMenu.addActionListener { retryVerbs(requestResponsesFromEvent(_Event),contentLength = true, json = false) }
        _RetryVerbsCLJSONJMenu.addActionListener { retryVerbs(requestResponsesFromEvent(_Event),contentLength = true, json = true) }
        _RetryWSJMenu.addActionListener { retryWebSockets() }
        _RequestURLsFromClipboard.addActionListener { requestURLsFromClipboard() }

        _ListOpenWSJMenu.addActionListener {
            listOpenWSConnections()
        }

        val label = JLabel("  Retry")
        label.isEnabled = false
        label.font = label.font.deriveFont(Font.BOLD)

        _MenuItemList = mutableListOf(label,_RetryRequestJMenu,_RetryVerbsJMenu,_RetryVerbsCLJMenu,_RetryVerbsCLJSONJMenu,_ListOpenWSJMenu,JSeparator())

        api.userInterface().registerHotKeyHandler(HotKey.hotKey("Retry Requests","Ctrl+Shift+E")) { event ->
            val requestResponses = requestResponsesFromEvent(event)
            retrySelectedRequests(requestResponses)
        }

    }

    fun listOpenWSConnections()
    {
        api.logging().logToOutput("Open WS Connections:")
        for(ws in proxyWebSockets) {
            api.logging().logToOutput("${ws.upgradeRequest().url()}")
        }
    }

    override fun provideMenuItems(event: ContextMenuEvent): List<Component> {
        _Event = event

        val menuList = if (!event.selectedRequestResponses()
                .isEmpty() || (event.messageEditorRequestResponse().isPresent && !event.messageEditorRequestResponse().isEmpty)
        ) {
            _MenuItemList.toMutableList()
        }
        else {
            mutableListOf()
        }

        if(updateRequestUrlsFromClipboard()) {
            val insertIndex = if(menuList.isEmpty()) 0 else menuList.lastIndex-1
            menuList.add(insertIndex, _RequestURLsFromClipboard)
        }


        return menuList
    }

    override fun provideMenuItems(event: WebSocketContextMenuEvent): List<Component> {
        _WSEvent=event
        if (!event.selectedWebSocketMessages().isEmpty() || event.messageEditorWebSocket().isPresent) {
            return mutableListOf(_RetryWSJMenu,_ListOpenWSJMenu)
        }
        return emptyList()
    }

    override fun provideMenuItems(event: AuditIssueContextMenuEvent): List<Component> {
        return emptyList()
    }

    private fun retrySelectedRequests(requestResponses: List<HttpRequestResponse>) {

        for (requestResponse in requestResponses) {
            myExecutor.runTask(RetryRequestsTask(api, requestResponse.request()))
        }
    }

    private fun retryWebSockets() {
        _WSEvent?.let { wsEvent ->
            listOpenWSConnections()
            val webSocketMessages: List<WebSocketMessage> = when {
                wsEvent.messageEditorWebSocket().isPresent ->
                    listOf(wsEvent.messageEditorWebSocket().get().webSocketMessage())
                !wsEvent.selectedWebSocketMessages().isEmpty() ->
                    wsEvent.selectedWebSocketMessages()
                else -> emptyList()
            }

            if (webSocketMessages.isNotEmpty()) {
                for (message in webSocketMessages) {
                    val search = message.upgradeRequest().url().replace(message.upgradeRequest().path(), "")
                    api.logging().logToOutput("Searching for candidate: ${message.upgradeRequest().url()} using ${search}")
                    for (proxyMessage in proxyWebSockets) {
                        if (proxyMessage.upgradeRequest().url().startsWith(search)) {
                            api.logging().logToOutput("Found candidate: ${proxyMessage.upgradeRequest().url()}")
                            proxyMessage.proxyWebSocket().sendBinaryMessage(message.payload(), message.direction())
                            break
                        }
                    }
                }
            }
        }
    }

    private fun retryVerbs(requestResponses: List<HttpRequestResponse>,contentLength: Boolean, json: Boolean) {

        for (requestResponse in requestResponses) {
            for (verb in _Verbs) {
                var newRequestResponse = requestResponse

                if (contentLength) {
                    if (!newRequestResponse.request().hasHeader("Content-Length")) {
                        newRequestResponse = HttpRequestResponse.httpRequestResponse(
                            newRequestResponse.request().withAddedHeader("Content-Length", "0"),
                            newRequestResponse.response()
                        )
                    }
                }

                if (json) {
                    newRequestResponse = if (newRequestResponse.request().hasHeader("Content-Type")) {
                        HttpRequestResponse.httpRequestResponse(
                            newRequestResponse.request().withUpdatedHeader("Content-Type", "application/json"),
                            newRequestResponse.response()
                        )
                    } else {
                        HttpRequestResponse.httpRequestResponse(
                            newRequestResponse.request().withAddedHeader("Content-Type", "application/json"),
                            newRequestResponse.response()
                        )
                    }

                    if (newRequestResponse.request().bodyToString().isEmpty() && !_VerbsNoBody.contains(verb)) {
                        newRequestResponse = HttpRequestResponse.httpRequestResponse(
                            newRequestResponse.request().withBody("{}"),
                            newRequestResponse.response()
                        )
                    }
                    if (_VerbsNoBody.contains(verb) && newRequestResponse.request().bodyToString().isNotEmpty()) {
                        // Intentionally send once with body, then clear and send again (as per original behavior)
                        myExecutor.runTask(RetryRequestsTask(api, newRequestResponse.request().withMethod(verb)))
                        newRequestResponse = HttpRequestResponse.httpRequestResponse(
                            newRequestResponse.request().withBody(""),
                            newRequestResponse.response()
                        )
                    }
                }

                myExecutor.runTask(RetryRequestsTask(api, newRequestResponse.request().withMethod(verb)))
            }
        }
    }

    private fun requestURLsFromClipboard() {
        _clipboardRequestUrls.forEach { url ->
            val request = HttpRequest.httpRequestFromUrl(url)
            myExecutor.runTask(RetryRequestsTask(api, request))
        }
    }

    // Combined logic helper used by overloaded requestResponses() functions
    private fun extractRequestResponses(
        hasSelected: () -> Boolean,
        selectedProvider: () -> MutableList<HttpRequestResponse>,
        editorIsPresent: () -> Boolean,
        editorIsEmpty: () -> Boolean,
        editorRequestResponseProvider: () -> HttpRequestResponse?
    ): List<HttpRequestResponse> {
        if (hasSelected()) {
            return selectedProvider()
        }

        if (editorIsPresent() && !editorIsEmpty()) {
            val rr = editorRequestResponseProvider()
            if (rr != null && rr.request() != null) {
                return mutableListOf(rr)
            }
        }
        return emptyList()
    }

    // Overload for ContextMenuEvent (nullable to match field usage)
    private fun requestResponsesFromEvent(event: ContextMenuEvent?): List<HttpRequestResponse> {
        if (event == null) return emptyList()
        return extractRequestResponses(
            hasSelected = { !event.selectedRequestResponses().isEmpty() },
            selectedProvider = { event.selectedRequestResponses() },
            editorIsPresent = { event.messageEditorRequestResponse().isPresent },
            editorIsEmpty = { event.messageEditorRequestResponse().isEmpty },
            editorRequestResponseProvider = { event.messageEditorRequestResponse().get().requestResponse() }
        )
    }

    // Overload for HotKeyEvent (kept for future hotkey handler wiring)
    private fun requestResponsesFromEvent(event: HotKeyEvent?): List<HttpRequestResponse> {
        if (event == null) return emptyList()
        return extractRequestResponses(
            hasSelected = { !event.selectedRequestResponses().isEmpty() },
            selectedProvider = { event.selectedRequestResponses() },
            editorIsPresent = { event.messageEditorRequestResponse().isPresent },
            editorIsEmpty = { event.messageEditorRequestResponse().isEmpty },
            editorRequestResponseProvider = { event.messageEditorRequestResponse().get().requestResponse() }
        )
    }

    /**
     * Checks the system clipboard for text content, extracts any http/https URLs,
     * and stores them into the class instance variable. If no URLs are found or
     * clipboard is not readable, clears the stored URLs.
     *
     * @return the list of URLs currently stored from the clipboard (empty if none)
     */
    fun updateRequestUrlsFromClipboard(): Boolean {
        val urls = try {
            val clipboard = Toolkit.getDefaultToolkit().systemClipboard
            val data = clipboard.getContents(null)
            if (data != null && data.isDataFlavorSupported(DataFlavor.stringFlavor)) {
                val text = data.getTransferData(DataFlavor.stringFlavor) as? String ?: ""
                extractUrls(text)
            } else {
                emptyList()
            }
        } catch (t: Throwable) {
            emptyList()
        }

        _clipboardRequestUrls = urls
        return _clipboardRequestUrls.isNotEmpty()
    }

    // Lightweight URL extractor/validator for http/https tokens
    private fun extractUrls(text: String): List<String> {
        if (text.isBlank()) return emptyList()
        return text
            .split("\n", "\r", "\t", " ")
            .asSequence()
            .map { it.trim() }
            .filter { it.startsWith("http://", ignoreCase = true) || it.startsWith("https://", ignoreCase = true) }
            .mapNotNull { candidate ->
                try {
                    val uri = URI(candidate)
                    if ((uri.scheme == "http" || uri.scheme == "https") && !uri.host.isNullOrBlank()) candidate else null
                } catch (_: Exception) {
                    null
                }
            }
            .distinct()
            .toList()
    }

//    override fun handle(event: HotKeyEvent) {
//
//            if(event.selectedRequestResponses().isNotEmpty()) {
//                val copyMe = buildString {
//
//                    event.selectedRequestResponses().forEach { reqRes->
//                        append(_copyHandler.copyItem(reqRes, _stripHeaders, _copyMode))
//                    }
//                }
//                _copyHandler.copyToClipboard(copyMe)
//            }
//            else if(event.messageEditorRequestResponse().isPresent) {
//                val requestResponse = event.messageEditorRequestResponse().get()
//                _copyHandler.copyToClipboard(
//                    _copyHandler.copyItem(requestResponse.requestResponse(), _stripHeaders, _copyMode)
//                )
//            }
//    }


}