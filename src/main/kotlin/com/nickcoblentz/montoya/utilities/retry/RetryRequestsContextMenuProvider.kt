package com.nickcoblentz.montoya.utilities

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.proxy.websocket.ProxyWebSocketCreation
import burp.api.montoya.ui.contextmenu.AuditIssueContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider
import burp.api.montoya.ui.contextmenu.WebSocketContextMenuEvent
import burp.api.montoya.ui.contextmenu.WebSocketMessage
import java.awt.Component
import java.awt.Font
import java.awt.event.ActionEvent
import java.awt.event.ActionListener
import javax.swing.JLabel
import javax.swing.JMenuItem
import javax.swing.JSeparator

class RetryRequestsContextMenuProvider(
    private val api: MontoyaApi, //private List<ProxyWebSocketCreation> proxyWebSockets;
    private val myExecutor: MyExecutor,
    private val proxyWebSockets: MutableList<ProxyWebSocketCreation>
) : ContextMenuItemsProvider, ActionListener {

    companion object {
        const val RETRY_REQUESTS: String = "RetryRequests"
        const val RETRY_VERBS: String = "RetryVerbs"
        const val RETRY_VERBS_CONTENT_LENGTH: String = "RetryVerbsWContentLength"
        const val RETRY_VERBS_CONTENT_LENGTH_JSON: String = "RetryVerbsWContentLengthJson"
        const val RETRY_WS: String = "Retry WS"
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
    private var _Event: ContextMenuEvent? = null
    private var _WSEvent : WebSocketContextMenuEvent? = null
    private val _ListOpenWSJMenu = JMenuItem("List Open WS Connections")

    init {
        //this.proxyWebSockets = proxyWebSockets;
        _RetryRequestJMenu.addActionListener(this)
        _RetryRequestJMenu.actionCommand = RETRY_REQUESTS
        _RetryVerbsJMenu.addActionListener(this)
        _RetryVerbsJMenu.actionCommand = RETRY_VERBS
        _RetryVerbsCLJMenu.addActionListener(this)
        _RetryVerbsCLJMenu.actionCommand = RETRY_VERBS_CONTENT_LENGTH
        _RetryVerbsCLJSONJMenu.addActionListener(this)
        _RetryVerbsCLJSONJMenu.actionCommand = RETRY_VERBS_CONTENT_LENGTH_JSON
        _RetryWSJMenu.addActionListener(this)
        _RetryWSJMenu.actionCommand = RETRY_WS

        _ListOpenWSJMenu.addActionListener {
            listOpenWSConnections()
        }

        val label = JLabel("  Retry")
        label.isEnabled = false
        label.font = label.font.deriveFont(Font.BOLD)

        _MenuItemList = mutableListOf(label,_RetryRequestJMenu,_RetryVerbsJMenu,_RetryVerbsCLJMenu,_RetryVerbsCLJSONJMenu,_ListOpenWSJMenu,
            JSeparator())


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

        if (!event.selectedRequestResponses()
                .isEmpty() || (event.messageEditorRequestResponse().isPresent && !event.messageEditorRequestResponse().isEmpty)
        ) {
            return _MenuItemList
        }

        return emptyList()
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

    override fun actionPerformed(actionEvent: ActionEvent) {
        val requestResponses = requestResponseFromEvent()

        if (actionEvent.actionCommand == RETRY_REQUESTS) {
            val count = 1
            val total = requestResponses.size
            for (requestResponse in requestResponses) {
                myExecutor.runTask(RetryRequestsTask(api, requestResponse.request()))
            }
        }
        else if(actionEvent.actionCommand == RETRY_WS)
        {
            _WSEvent?.let { wsEvent ->
                listOpenWSConnections()
                val webSocketMessages : List<WebSocketMessage> = if(wsEvent.messageEditorWebSocket().isPresent)
                    listOf(wsEvent.messageEditorWebSocket().get().webSocketMessage())
                else if(!wsEvent.selectedWebSocketMessages().isEmpty())
                    wsEvent.selectedWebSocketMessages()
                else
                    emptyList<WebSocketMessage>()

                if(!webSocketMessages.isEmpty()) {
                    for(message in webSocketMessages) {
                        val search = message.upgradeRequest().url().replace(message.upgradeRequest().path(),"")
                        api.logging().logToOutput("Searching for candidate: ${message.upgradeRequest().url()} using ${search}")
                        for(proxyMessage in proxyWebSockets) {
                            if(proxyMessage.upgradeRequest().url().startsWith(search)) {
                                api.logging().logToOutput("Found candidate: ${proxyMessage.upgradeRequest().url()}")
                                proxyMessage.proxyWebSocket().sendBinaryMessage(message.payload(),message.direction())
                                break
                            }
                        }
                    }
                }
            }
        }
        else {
            val total = requestResponses.size * _Verbs.size
            val count = 1
            for (requestResponse in requestResponses) {
                for (verb in _Verbs) {
                    var newRequestResponse = requestResponse

                    if (actionEvent.actionCommand == RETRY_VERBS_CONTENT_LENGTH || actionEvent.actionCommand == RETRY_VERBS_CONTENT_LENGTH_JSON) {
                        if (!newRequestResponse.request().hasHeader("Content-Length")) {
                            newRequestResponse = HttpRequestResponse.httpRequestResponse(
                                newRequestResponse.request().withAddedHeader("Content-Length", "0"),
                                newRequestResponse.response()
                            )
                        }
                    }

                    if (actionEvent.actionCommand == RETRY_VERBS_CONTENT_LENGTH_JSON) {
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

                        if (newRequestResponse.request().bodyToString()
                                .isEmpty() && !_VerbsNoBody.contains(verb)
                        ) newRequestResponse = HttpRequestResponse.httpRequestResponse(
                            newRequestResponse.request().withBody("{}"),
                            newRequestResponse.response()
                        )
                        if (_VerbsNoBody.contains(verb) && !newRequestResponse.request().bodyToString().isEmpty()) {
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
    }

    private fun requestResponseFromEvent() : List<HttpRequestResponse> {
            var result: MutableList<HttpRequestResponse> = ArrayList()
            _Event?.let {
                if (!it.selectedRequestResponses().isEmpty()) {
                    result = it.selectedRequestResponses()
                } else if (it.messageEditorRequestResponse().isPresent && !it.messageEditorRequestResponse().isEmpty) {
                    if (it.messageEditorRequestResponse().get().requestResponse().request() != null) {
                        result.add(it.messageEditorRequestResponse().get().requestResponse())
                        return result
                    }
                }
            }

            return result
        }
}