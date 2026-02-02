package com.nickcoblentz.montoya.websocket

import MyExtensionSettings
import burp.api.montoya.MontoyaApi
import burp.api.montoya.proxy.websocket.*
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider
import burp.api.montoya.ui.contextmenu.WebSocketContextMenuEvent
import burp.api.montoya.ui.contextmenu.WebSocketMessage
import burp.api.montoya.ui.editor.EditorOptions
import com.nickcoblentz.montoya.LogLevel
import com.nickcoblentz.montoya.MontoyaLogger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.cancel
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import java.util.concurrent.Executors
import java.awt.*
import javax.swing.*

class MontoyaWSUtils(private val api: MontoyaApi, private val myExtensionSettings : MyExtensionSettings) : ContextMenuItemsProvider, ProxyWebSocketCreationHandler {

    companion object {
        const val EXTENSION_NAME = "WS Utils"
        const val DEFAULT_WS_REQUEST_LIMIT = 25
    }

    private var logger = MontoyaLogger(api, LogLevel.DEBUG)

    private var selectedProxyCreation: ProxyWebSocketCreation? = null
    private val proxyWebSocketCreations = mutableListOf<ProxyWebSocketCreation>()
    private var webSocketMessages: MutableList<WebSocketMessage> = mutableListOf()


    private var currentThreadLimit = DEFAULT_WS_REQUEST_LIMIT
    private var semaphore = Semaphore(currentThreadLimit)
    private val virtualExecutor = Executors.newVirtualThreadPerTaskExecutor()
    private val virtualDispatcher = virtualExecutor.asCoroutineDispatcher()
    private val scope = CoroutineScope(SupervisorJob() + virtualDispatcher)

    private val showUpgradeRequestMenuItem = JMenuItem("Show Upgrade Request")
    private val showIntruderIntegerMenu = JMenuItem("Intruder: Integers")

    val label = JLabel("  WS Utils").apply {
        isEnabled = false
        font = font.deriveFont(Font.BOLD)
    }

    private val allMenuItems = mutableListOf<Component>(
        label,
        showUpgradeRequestMenuItem,
        showIntruderIntegerMenu,
        JSeparator()
    )

    private var selectedWebSocketMessage: WebSocketMessage? = null

    fun shutdown() {
        scope.cancel()
        virtualExecutor.shutdown()
    }

    private fun updateConcurrencyLimit() {
        if (myExtensionSettings.wsRequestLimit != currentThreadLimit) {
            currentThreadLimit = myExtensionSettings.wsRequestLimit
            semaphore = Semaphore(currentThreadLimit)
        }
        logger.debugLog("WebSocket Request Limit set to: $currentThreadLimit")
    }

    init {


        // This will print to Burp Suite's Extension output and can be used to debug whether the extension loaded properly
        logger.debugLog("Started loading the extension...")


//        api.extension().setName(EXTENSION_NAME)




        updateConcurrencyLimit()

        showUpgradeRequestMenuItem.addActionListener {
            webSocketMessages.forEach { message ->
                message.upgradeRequest()?.let { upgradeRequest ->
                    val requestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY, EditorOptions.WRAP_LINES)
                    requestEditor.request=upgradeRequest
                    val burpFrame = BurpGuiFrame("HTTP Request Editor - " + upgradeRequest.url())

                    burpFrame.frame.contentPane.add(requestEditor.uiComponent(), BorderLayout.CENTER)
                    burpFrame.showFrame()
                }
            }
        }

        showIntruderIntegerMenu.addActionListener {
            webSocketMessages.forEach { message ->
                val burpFrame = BurpGuiFrame("WS Intruder")

                val webSocketConnectionsComboBox = JComboBox(proxyWebSocketCreations.indices.map { index ->
                    val creation = proxyWebSocketCreations[index]
                    val item = "$index ${creation.upgradeRequest().url()}"
                    logger.debugLog("Adding item to combo box: $item")
                    item
                }.reversed().toTypedArray())

                val startIntegerField = JTextField("0", 10) // Default start value, 10 columns wide
                val endIntegerField = JTextField("100", 10) // Default end value, 10 columns wide
                val replaceField = JTextField("REPLACEME", 10) // Default end value, 10 columns wide


                val mainPanel = JPanel(GridBagLayout())
                val gbc = GridBagConstraints()
                gbc.insets = Insets(5, 5, 5, 5) // Padding

                // WebSocket Connections Label and ComboBox
                gbc.gridx = 0
                gbc.gridy = 0
                gbc.anchor = GridBagConstraints.WEST
                mainPanel.add(JLabel("Select WebSocket Connection:"), gbc)

                gbc.gridx = 1
                gbc.gridy = 0
                gbc.fill = GridBagConstraints.HORIZONTAL
                mainPanel.add(webSocketConnectionsComboBox, gbc)

                // Starting Integer Label and Field
                gbc.gridx = 0
                gbc.gridy = 1
                gbc.fill = GridBagConstraints.NONE // Reset fill
                mainPanel.add(JLabel("Starting Integer:"), gbc)

                gbc.gridx = 1
                gbc.gridy = 1
                gbc.fill = GridBagConstraints.HORIZONTAL
                mainPanel.add(startIntegerField, gbc)

                // Ending Integer Label and Field
                gbc.gridx = 0
                gbc.gridy = 2
                gbc.fill = GridBagConstraints.NONE
                mainPanel.add(JLabel("Ending Integer:"), gbc)

                gbc.gridx = 1
                gbc.gridy = 2
                gbc.fill = GridBagConstraints.HORIZONTAL
                mainPanel.add(endIntegerField, gbc)


                gbc.gridx = 0
                gbc.gridy = 3
                gbc.fill = GridBagConstraints.NONE
                mainPanel.add(JLabel("Replace This String (All Instances):"), gbc)

                gbc.gridx = 1
                gbc.gridy = 3
                gbc.fill = GridBagConstraints.HORIZONTAL
                mainPanel.add(replaceField, gbc)


                // Buttons Panel
                val buttonPanel = JPanel(FlowLayout(FlowLayout.RIGHT))
                val startButton = JButton("Start")

                startButton.addActionListener {
                    updateConcurrencyLimit()
                    val startInteger = startIntegerField.text.toInt()
                    val endInteger = endIntegerField.text.toInt()
                    val replaceString = replaceField.text

                    val selectedWebSocketConnection = webSocketConnectionsComboBox.selectedItem as String
                    selectedWebSocketConnection.substringBefore(" ").toIntOrNull()?.let { index ->
                        logger.debugLog("Starting WS Intruder on connection $index")

                        logger.debugLog("Replace Value Found?: ${message.payload().toString().contains(replaceString)}")

                        selectedProxyCreation = proxyWebSocketCreations[index]

                        for (i in startInteger..endInteger) {
                            scope.launch {
                                semaphore.withPermit {
                                    try {
                                        val newMessage = message.payload().toString().replace(replaceString, i.toString())
                                        logger.debugLog("Current Progress ====================\n$startInteger <= $i <= $endInteger \n${selectedProxyCreation} ${selectedProxyCreation?.proxyWebSocket()}\n-------------------")
                                        if (proxyWebSocketCreations.contains(selectedProxyCreation)) {
                                            logger.debugLog("Sending Message (${message.direction()}):\n$newMessage\n-----------------")
                                            selectedProxyCreation?.proxyWebSocket()?.sendTextMessage(newMessage, message.direction())
                                        } else {
                                            logger.debugLog("Proxy WebSocket Connection is no longer there...")
                                            logger.errorLog("Proxy WebSocket Connection is no longer there... $index: ${selectedProxyCreation?.upgradeRequest()?.url()}")
                                        }
                                    } catch (e: Exception) {
                                        logger.errorLog("Error running coroutine: ${e.message}\n${e.stackTraceToString()}")
                                    }
                                }
                            }
                        }
                    }
                }

                val cancelButton = JButton("Cancel")

                cancelButton.addActionListener {
                    burpFrame.frame.dispose()
                }

                buttonPanel.add(cancelButton)
                buttonPanel.add(startButton)

                gbc.gridx = 0
                gbc.gridy = 4
                gbc.gridwidth = 2 // Span across two columns
                gbc.anchor = GridBagConstraints.CENTER
                mainPanel.add(buttonPanel, gbc)

                burpFrame.frame.contentPane.add(mainPanel, BorderLayout.CENTER)

                burpFrame.showFrame()
            }
        }

        api.userInterface().registerContextMenuItemsProvider(this)

        api.proxy().registerWebSocketCreationHandler(this)

        // Code for setting up your extension ends here

        // See logging comment above
        logger.debugLog("...Finished loading the extension")

    }




    override fun provideMenuItems(event: WebSocketContextMenuEvent?): List<Component> {

        webSocketMessages.clear()
        event?.let { e ->
            if(e.messageEditorWebSocket().isPresent) {
                webSocketMessages = mutableListOf(e.messageEditorWebSocket().get().webSocketMessage())
            }
            if(e.selectedWebSocketMessages().isNotEmpty()) {
                webSocketMessages = e.selectedWebSocketMessages()
            }

            if(webSocketMessages.isNotEmpty()) {
                return allMenuItems
            }
        }
        return listOf()
    }

    override fun handleWebSocketCreation(proxyWebSocketCreation: ProxyWebSocketCreation?) {
        proxyWebSocketCreation?.let {creation ->
            creation.proxyWebSocket().registerProxyMessageHandler((object : ProxyMessageHandler {
                override fun handleTextMessageReceived(interceptedTextMessage: InterceptedTextMessage): TextMessageReceivedAction {
                    return TextMessageReceivedAction.continueWith(interceptedTextMessage)
                }

                override fun handleTextMessageToBeSent(interceptedTextMessage: InterceptedTextMessage?): TextMessageToBeSentAction {
                    return TextMessageToBeSentAction.continueWith(interceptedTextMessage)
                }

                override fun handleBinaryMessageReceived(interceptedBinaryMessage: InterceptedBinaryMessage?): BinaryMessageReceivedAction {
                    return BinaryMessageReceivedAction.continueWith(interceptedBinaryMessage)
                }

                override fun handleBinaryMessageToBeSent(interceptedBinaryMessage: InterceptedBinaryMessage?): BinaryMessageToBeSentAction {
                    return BinaryMessageToBeSentAction.continueWith(interceptedBinaryMessage)
                }

                override fun onClose() {
                    super.onClose()
                    proxyWebSocketCreations.remove(creation)
                    logger.debugLog("Removing one - closed")

                    if(myExtensionSettings.wsBumpWSConnection && selectedProxyCreation != null) {
                        selectedProxyCreation = proxyWebSocketCreations.lastOrNull()
                    }

                }
            }))
            proxyWebSocketCreations.add(creation)
            logger.debugLog("WebSocket Connection Created: ${creation.upgradeRequest().url()}")
        }
    }


}


