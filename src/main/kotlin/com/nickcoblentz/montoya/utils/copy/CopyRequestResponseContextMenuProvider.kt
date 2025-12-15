package com.nickcoblentz.montoya.utils

import burp.api.montoya.MontoyaApi

import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.ui.contextmenu.*
import burp.api.montoya.ui.hotkey.HotKeyHandler
import com.nickcoblentz.montoya.LogLevel
import com.nickcoblentz.montoya.MontoyaLogger
import java.awt.Component
import java.awt.Dimension
import java.awt.Font
import java.awt.event.ActionEvent
import java.awt.event.ActionListener
import java.util.*
import javax.swing.JLabel
import javax.swing.JMenuItem
import javax.swing.JOptionPane
import javax.swing.JScrollPane
import javax.swing.JSeparator
import javax.swing.JTextArea
import javax.swing.SwingUtilities

class CopyRequestResponseContextMenuProvider(private val _api: MontoyaApi, private val _copyHandler: CopyRequestResponseHandler) : ContextMenuItemsProvider, ActionListener {
    private val _MenuItemList: List<Component>
    private var currentEvent: ContextMenuEvent? = null
    private var currentWSEvent: WebSocketContextMenuEvent? = null
    private var currentAuditEvent: AuditIssueContextMenuEvent? = null
    private var currentEventType = 0

    private val _EventTypeHTTP = 1
    private val _EventTypeWS = 2
    private val _EventTypeAudit = 3
    private val _CopyRequestAndResponseName = "Full Rq/Rs"
    private val _CopyRequestAndResponseHeaderName = "Full Rq, Rs Header"
    private val _CopyURLAndResponseName = "URL, Rs"
    private val _CopyURLAndResponseHeaderName = "URL, Rs Header"
    private val _CopyRequestAndResponseIncludeName = "Full Rq/Rs (incl. all)"
    private val _CopyURLAndResponseHeaderIncludeName = "URL, Rs Header (incl. all)"
    private val _CopyResponseBodyOnlyName = "Rs Body Only"


    private val _CopyRequestAndResponseJMenuItem = JMenuItem(_CopyRequestAndResponseName)
    private val _CopyRequestAndResponseHeaderJMenuItem = JMenuItem(_CopyRequestAndResponseHeaderName)
    private val _CopyURLAndResponseJMenuItem = JMenuItem(_CopyURLAndResponseName)
    private val _CopyURLAndResponseHeadersJMenuItem = JMenuItem(_CopyURLAndResponseHeaderName)
    private val _CopyRequestAndResponseIncludeJMenuItem = JMenuItem(_CopyRequestAndResponseIncludeName)
    private val _CopyURLAndResponseHeaderIncludeJMenuItem = JMenuItem(_CopyURLAndResponseHeaderIncludeName)
    private val _CopyResponseBodyOnlyJMenuItem = JMenuItem(_CopyResponseBodyOnlyName)
    private val _SearchAndExtractJmenuItem = JMenuItem("Search and Extract")

    var logger: MontoyaLogger = MontoyaLogger(_api, LogLevel.DEBUG)

    init {
        _CopyRequestAndResponseHeaderJMenuItem.addActionListener(this)
        _CopyRequestAndResponseJMenuItem.addActionListener(this)
        _CopyURLAndResponseJMenuItem.addActionListener(this)
        _CopyURLAndResponseHeadersJMenuItem.addActionListener(this)
        _CopyRequestAndResponseIncludeJMenuItem.addActionListener(this)
        _CopyURLAndResponseHeaderIncludeJMenuItem.addActionListener(this)
        _CopyResponseBodyOnlyJMenuItem.addActionListener(this)

        _SearchAndExtractJmenuItem.addActionListener{ e->
            searchAndExtractAction(e)
        }

        val label = JLabel("  Copy")
        label.isEnabled = false
        label.font = label.font.deriveFont(Font.BOLD)
        _MenuItemList = listOf(
            label,
            _CopyRequestAndResponseJMenuItem,
            _CopyRequestAndResponseHeaderJMenuItem,
            _CopyURLAndResponseJMenuItem,
            _CopyURLAndResponseHeadersJMenuItem,
            _CopyRequestAndResponseIncludeJMenuItem,
            _CopyURLAndResponseHeaderIncludeJMenuItem,
            _CopyResponseBodyOnlyJMenuItem,
            _SearchAndExtractJmenuItem,
            JSeparator())
    }

    override fun provideMenuItems(event: ContextMenuEvent): List<Component> {
        currentEvent = event
        currentEventType = _EventTypeHTTP
        if (!event.selectedRequestResponses().isEmpty() || event.messageEditorRequestResponse().isPresent) {
            return _MenuItemList
        }
        return emptyList<Component>()
    }

    override fun provideMenuItems(event: WebSocketContextMenuEvent): List<Component> {
        currentWSEvent = event
        currentEventType = _EventTypeWS
        if (!event.selectedWebSocketMessages().isEmpty() || event.messageEditorWebSocket().isPresent) {
            return _MenuItemList
        }
        return emptyList<Component>()
    }

    override fun provideMenuItems(event: AuditIssueContextMenuEvent): List<Component> {
        currentAuditEvent = event
        currentEventType = _EventTypeAudit
        if (event.selectedIssues().isNotEmpty()) {
            return _MenuItemList
        }
        return emptyList<Component>()
    }

    private fun searchAndExtractAction(e: ActionEvent) {

        SwingUtilities.invokeLater {
            val regexInput = JOptionPane.showInputDialog(
                _api.userInterface().swingUtils().suiteFrame(),
                "Enter Regular Expression (e.g., 'Authorization: (.*)'):",
                "Regex Extractor",
                JOptionPane.QUESTION_MESSAGE
            )

            if (!regexInput.isNullOrEmpty()) {
                processSearchAndExtract(e, regexInput)
            }
        }
    }

    private fun processSearchAndExtract(e: ActionEvent, regexInput: String) {
        Thread.ofVirtual().start {
            val selectedRequestResponses = if (currentEventType == _EventTypeHTTP) {
                if (currentEvent?.selectedRequestResponses()?.isNotEmpty() ?: false) {
                    currentEvent!!.selectedRequestResponses().flatMap { it -> listOf(it.request().toString(),it.response().toString()) }
                } else if (currentEvent!!.messageEditorRequestResponse().isPresent) {
                    listOf(currentEvent!!.messageEditorRequestResponse().get().requestResponse().request().toString(),currentEvent!!.messageEditorRequestResponse().get().requestResponse().response().toString())
                } else {
                    listOf<String>()
                }
            } else if (currentEventType == _EventTypeWS) {
                if (currentWSEvent?.selectedWebSocketMessages()?.isNotEmpty() ?: false) {
                    currentWSEvent!!.selectedWebSocketMessages().map { it -> it.payload().toString() }
                } else if (currentWSEvent?.messageEditorWebSocket()?.isPresent ?: false) {
                    mutableListOf(currentWSEvent!!.messageEditorWebSocket().get().webSocketMessage().payload().toString())
                } else {
                    mutableListOf<String>()
                }
            } else {
                currentAuditEvent?.let { event ->
                    event.selectedIssues().flatMap { it.requestResponses().flatMap { it -> listOf(it.request().toString(),it.response().toString()) } }
                }
            }

            val regex = regexInput.toRegex(setOf(RegexOption.IGNORE_CASE,RegexOption.MULTILINE))
            val sb = StringBuilder()
            var matchCount = 0
            selectedRequestResponses?.forEach { item ->
                // Convert request body/headers to string

                // Find all matches in the request
                val matches = regex.findAll(item)

                if (matches.any()) {
                    matches.forEach { matchResult ->
                        matchCount++
//                        sb.append("Full Match: \"${matchResult.value}\"\n")

                        // Iterate over capture groups (Group 0 is full match, so we skip it to show specific groups)
                        if (matchResult.groupValues.size > 1) {
                            matchResult.groupValues.forEachIndexed { index, groupVal ->
                                if (index > 0) { // Skip group 0 (the whole match)
                                    sb.append(groupVal+"\n")
                                }
                            }
                        }
                    }
                }
            }

            // Show results back on the Event Dispatch Thread
            SwingUtilities.invokeLater {
                if (sb.isNotEmpty()) {
                    displayResults(sb.toString(),matchCount)
                } else {
                    JOptionPane.showMessageDialog(null, "No matches found for regex: $regexInput")
                }
            }
        }
    }

    private fun displayResults(results: String, count: Int) {
        val textArea = JTextArea(results)
        textArea.isEditable = false

        val scrollPane = JScrollPane(textArea)
        scrollPane.preferredSize = Dimension(600, 400)

        JOptionPane.showMessageDialog(
            _api.userInterface().swingUtils().suiteFrame(),
            scrollPane,
            "Extraction Results ($count matches)",
            JOptionPane.INFORMATION_MESSAGE
        )
    }

    override fun actionPerformed(e: ActionEvent) {

        if (currentEventType == _EventTypeWS) {
            handleWSEvent(e)
        }
        else if(currentEventType == _EventTypeHTTP) {
            handleHTTPEvent(e)
        }
        else {
            handleAuditEvent(e)
        }
    }

    private fun handleWSEvent(e: ActionEvent?) {
        val targetWebSocketMessages: MutableList<WebSocketMessage>
        if (!currentWSEvent!!.selectedWebSocketMessages().isEmpty()) {
            targetWebSocketMessages = currentWSEvent!!.selectedWebSocketMessages()
        } else if (currentWSEvent!!.messageEditorWebSocket().isPresent) {
            targetWebSocketMessages = LinkedList()
            targetWebSocketMessages.add(currentWSEvent!!.messageEditorWebSocket().get().webSocketMessage())
        } else {
            return
        }

        _copyHandler.copyToClipboard(
            _copyHandler.copyItemsWS(targetWebSocketMessages)
        )

    }

    private fun handleAuditEvent(e: ActionEvent?) {

        currentAuditEvent?.let { event ->
            var requestResponses = mutableListOf<HttpRequestResponse>()
            for(selectedIssue in event.selectedIssues()) {
                selectedIssue.requestResponses()?.let {
                    requestResponses.addAll(it)
                }
                /* later
                selectedIssue.collaboratorInteractions()?.let { interactions ->
                    for(interaction in interactions) {
                        interaction.
                    }
                }*/
            }
            _copyHandler.copyToClipboard(
                _copyHandler.copyItemsHTTP(requestResponses)
            )
        }
    }

    private fun handleHTTPEvent(e: ActionEvent) {
        val targetRequestResponses: MutableList<HttpRequestResponse>
        if (!currentEvent!!.selectedRequestResponses().isEmpty()) {
            targetRequestResponses = currentEvent!!.selectedRequestResponses()
        } else if (currentEvent!!.messageEditorRequestResponse().isPresent) {
            targetRequestResponses = LinkedList()
            targetRequestResponses.add(currentEvent!!.messageEditorRequestResponse().get().requestResponse())
        } else {
            return
        }

        _copyHandler.copyToClipboard(
            _copyHandler.copyItemsHTTP(targetRequestResponses,shouldStripHeaders(e.actionCommand),resolveCopyMode(e.actionCommand))
        )
    }

    private fun shouldStripHeaders(actionCommand : String) : Boolean = listOf(_CopyRequestAndResponseName,_CopyRequestAndResponseHeaderName,_CopyURLAndResponseName,_CopyURLAndResponseHeaderName).contains(actionCommand)

    private fun resolveCopyMode(actionCommand : String) : CopyRequestResponseHandler.CopyMode = when(actionCommand) {
        _CopyRequestAndResponseName -> CopyRequestResponseHandler.CopyMode.RequestFullResponseFull
        _CopyRequestAndResponseHeaderName -> CopyRequestResponseHandler.CopyMode.RequestFullResponseHeaders
        _CopyURLAndResponseName -> CopyRequestResponseHandler.CopyMode.URLResponseFull
        _CopyURLAndResponseHeaderName -> CopyRequestResponseHandler.CopyMode.URLResponseHeaders
        _CopyRequestAndResponseIncludeName -> CopyRequestResponseHandler.CopyMode.RequestFullResponseFull
        _CopyURLAndResponseHeaderIncludeName -> CopyRequestResponseHandler.CopyMode.URLResponseHeaders
        _CopyResponseBodyOnlyName -> CopyRequestResponseHandler.CopyMode.ResponseBody
        else -> CopyRequestResponseHandler.CopyMode.RequestFullResponseFull
    }
}