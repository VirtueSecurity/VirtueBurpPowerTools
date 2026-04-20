package com.nickcoblentz.montoya

import MyExtensionSettings
import SmartScanUI
import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ToolType
import burp.api.montoya.http.handler.HttpHandler
import burp.api.montoya.http.handler.HttpRequestToBeSent
import burp.api.montoya.http.handler.HttpResponseReceived
import burp.api.montoya.http.handler.RequestToBeSentAction
import burp.api.montoya.http.handler.ResponseReceivedAction
import burp.api.montoya.http.message.params.HttpParameter
import burp.api.montoya.http.message.requests.HttpRequest
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.jsonObject
import java.nio.file.Path
import kotlin.io.path.exists
import kotlin.io.path.readText
import kotlin.time.Duration.Companion.seconds

class SmartScanExtension(private val api: MontoyaApi, private val myExtensionSettings : MyExtensionSettings) {

    private val logger: MontoyaLogger = MontoyaLogger(api, LogLevel.DEBUG)
    private val pluginName = "SmartScan"


    init {
        logger.debugLog("Started loading the $pluginName extension...")

        api.extension().registerUnloadingHandler {
            logger.debugLog("Unloading the $pluginName extension...")

        }

        val viewModel = SmartScanViewModel(api, myExtensionSettings)
        val aiHttphandler = AIHTTPHandler(api, myExtensionSettings, viewModel)
        val crawlHttpHandler = CrawlHttpHandler(api, myExtensionSettings, viewModel)
        val scannerMonitorHttpHandler = ScannerMonitorHttpHandler(api, viewModel)

        api.http().registerHttpHandler(aiHttphandler)
        api.http().registerHttpHandler(crawlHttpHandler)
        api.http().registerHttpHandler(scannerMonitorHttpHandler)

        val smartScanUI = SmartScanUI(api, viewModel)
        api.userInterface().registerSuiteTab(pluginName, smartScanUI.getRootComponent())
        logger.debugLog("Finished loading the $pluginName extension...")
    }



}