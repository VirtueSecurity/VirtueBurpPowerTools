package com.nickcoblentz.montoya.utilities

import MyExtensionSettings
import burp.api.montoya.MontoyaApi
import burp.api.montoya.proxy.websocket.*
import burp.api.montoya.ui.hotkey.HotKey
import burp.api.montoya.ui.settings.SettingsPanelBuilder
import burp.api.montoya.ui.settings.SettingsPanelPersistence
import com.nickcoblentz.montoya.LogLevel
import com.nickcoblentz.montoya.MontoyaLogger
import com.nickcoblentz.montoya.settings.PanelSettingsDelegate
import com.nickcoblentz.montoya.utils.CopyRequestResponseHandler
import com.nickcoblentz.montoya.utils.CopyRequestResponseHotKeyProvider
import kotlinx.coroutines.cancel

class RetryRequestsMontoya(private val api: MontoyaApi, private val myExtensionSettings : MyExtensionSettings) : ProxyWebSocketCreationHandler {
    private var logger: MontoyaLogger = MontoyaLogger(api,LogLevel.DEBUG)
    private var myExecutor: MyExecutor

    private val proxyWebSockets = mutableListOf<ProxyWebSocketCreation>()

    init {

        logger.debugLog("Started loading Retry Requests...")

//        api.extension().setName("Retry Requests")


        myExecutor = MyExecutor(api,myExtensionSettings)
        api.extension().registerUnloadingHandler { myExecutor.shutdown() }
        val retryContenxtMenuProvider = RetryRequestsContextMenuProvider(api, myExecutor,proxyWebSockets)
        api.userInterface().registerContextMenuItemsProvider(retryContenxtMenuProvider)
        api.proxy().registerWebSocketCreationHandler(this)

//        api.userInterface().registerHotKeyHandler(
//            HotKey.hotKey("Retry Requests","Ctrl+Shift+E"),retryContenxtMenuProvider
//            )


        logger.debugLog("...Finished loading Retry Requests")
    }


    override fun handleWebSocketCreation(proxyWebSocketCreation: ProxyWebSocketCreation?) {
        proxyWebSocketCreation?.let {
            it.proxyWebSocket().registerProxyMessageHandler(object : ProxyMessageHandler {
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
                    proxyWebSockets.remove(it)
                    logger.debugLog("Removing one - closed")

                }
            })
            proxyWebSockets.add(it)
            logger.debugLog("Added: one")

        }


    }

}

//class MyExtensionSettings {
//    val settingsPanelBuilder : SettingsPanelBuilder = SettingsPanelBuilder.settingsPanel()
//        .withPersistence(SettingsPanelPersistence.PROJECT_SETTINGS)
//        .withTitle("Retry Requests")
//        .withDescription("Update Settings")
//        .withKeywords("Retry")
//
//    private val settingsManager = PanelSettingsDelegate(settingsPanelBuilder)
//
//    val limitConcurrentRequestsSetting: Boolean by settingsManager.booleanSetting("Limit the number of concurrent HTTP requests?", false)
//    val requestLimit: Int by settingsManager.integerSetting("Concurrent HTTP Request Limit", 10)
//
//
//
//    val settingsPanel = settingsManager.buildSettingsPanel()
//
//
//}
