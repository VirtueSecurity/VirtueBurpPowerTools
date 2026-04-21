package com.nickcoblentz.montoya

import MyExtensionSettings
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
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.exists
import kotlin.io.path.getLastModifiedTime
import kotlin.io.path.readText
import kotlin.time.Duration.Companion.seconds

@Serializable
data class SessionData(
    val authenticated: Boolean,
    val cookies: Map<String, String>,
    val headers: Map<String, String>,
)

class AIHTTPHandler(
    private val api: MontoyaApi,
    private val myExtensionSettings: MyExtensionSettings,
    private val viewModel: SmartScanViewModel? = null
) :
    HttpHandler {

    private val logger: MontoyaLogger = MontoyaLogger(api, LogLevel.DEBUG)
    private val pluginName = "AI HTTP Handler"
    private val json = Json {
        isLenient = true
        ignoreUnknownKeys = true // Often used together for maximum flexibility
    }


    init {
        logger.debugLog("Started loading the $pluginName extension...")

        api.extension().registerUnloadingHandler {
            logger.debugLog("Unloading the $pluginName extension...")

        }

        api.http().registerHttpHandler(this)

        logger.debugLog("Finished loading the $pluginName extension...")
    }


    override fun handleHttpRequestToBeSent(requestToBeSent: HttpRequestToBeSent): RequestToBeSentAction {

        if(!myExtensionSettings.aiSessionHandlerEnabled) {
            logger.debugLog("AI Session Handler Not Enabled")
            return RequestToBeSentAction.continueWith(requestToBeSent)
        }

        val toolEnabled = when (requestToBeSent.toolSource().toolType()) {
            ToolType.REPEATER -> myExtensionSettings.aiSessionHandlerRepeaterEnabled
            ToolType.SCANNER -> myExtensionSettings.aiSessionHandlerScannerEnabled
            ToolType.EXTENSIONS -> myExtensionSettings.aiSessionHandlerExtensionsEnabled
            ToolType.INTRUDER -> myExtensionSettings.aiSessionHandlerIntruderEnabled
            else -> false
        }

        if(!toolEnabled) {
            logger.debugLog("Tool not enabled. from: ${requestToBeSent.toolSource().toolType()}")
            return RequestToBeSentAction.continueWith(requestToBeSent)
        }

        if(requestToBeSent.toolSource().toolType() !in listOf(ToolType.REPEATER, ToolType.SCANNER)) {
            logger.debugLog("AI Session Handler Tool Not Enabled")
            return RequestToBeSentAction.continueWith(requestToBeSent)
        }

        if(!requestToBeSent.isInScope) {
            logger.debugLog("AI Session Handler Request Not In Scope")
            return RequestToBeSentAction.continueWith(requestToBeSent)
        }

        if(myExtensionSettings.aiSessionHandlerProjectJSONPath.isBlank()) {
            logger.debugLog("AI Session Handler Project.json path empty")
            viewModel?.logError("AI Session Handler Project.json path is empty in settings")
            return RequestToBeSentAction.continueWith(requestToBeSent)
        }

        val sessionData = getProjectJsonSession()
        
        if (sessionData == null || !sessionData.authenticated) {
            val errorMessage = "AI Session Handler: Authentication missing or session data not available. Request sent without AI session modifications: ${requestToBeSent.url()}"
            
            // 1. Extension Log (via MontoyaLogger)
            logger.errorLog(errorMessage)
            
            // 2. Burp Event Log
            api.logging().raiseInfoEvent(errorMessage)
            
            // 3. SmartScan Log (via ViewModel)
            viewModel?.logError(errorMessage)
            
            return RequestToBeSentAction.continueWith(requestToBeSent)
        }

        var httpRequest: HttpRequest = requestToBeSent
        sessionData.let { data ->
            data.cookies.forEach { (name, value) ->
                val cookieParam = HttpParameter.cookieParameter(name, value)
                logger.debugLog("Adding cookie: $name: $value")
                httpRequest = httpRequest.withParameter(cookieParam)
            }
            data.headers.forEach { (name, value) ->
                logger.debugLog("Adding header: $name: $value")
                httpRequest = httpRequest.withAddedOrUpdatedHeader(name, value)
            }
        }
        return RequestToBeSentAction.continueWith(httpRequest)
    }

    override fun handleHttpResponseReceived(responseReceived: HttpResponseReceived): ResponseReceivedAction {
        return ResponseReceivedAction.continueWith(responseReceived)
    }

    private var lastSessionData: SessionData? = null
    private var lastSessionFetchTime: Long = 0
    private var lastFileModifiedTime: Long = 0
    private val SESSION_CACHE_DURATION_MS = 1000L

    private fun getProjectJsonSession() : SessionData? {
        val now = System.currentTimeMillis()
        if (now - lastSessionFetchTime < SESSION_CACHE_DURATION_MS) {
            return lastSessionData
        }

        val pathStr = myExtensionSettings.aiSessionHandlerProjectJSONPath
        if(pathStr.isBlank()) return null
        val path = Path.of(pathStr)
        if(!path.exists()) {
            logger.errorLog("Couldn't parse project.json: ${path.toString()} does not exist")
            viewModel?.logError("AI HTTP Handler: project.json does not exist at $pathStr")
            lastSessionFetchTime = now // Still update time to avoid spamming the error
            return null
        }
        
        try {
            val currentModifiedTime = Files.getLastModifiedTime(path).toMillis()
            if (currentModifiedTime == lastFileModifiedTime && lastSessionData != null) {
                lastSessionFetchTime = now
                return lastSessionData
            }

            val text = path.readText()
            if(text.isBlank()) {
                logger.errorLog("Couldn't parse project.json: ${path.toString()} is blank")
                viewModel?.logError("AI HTTP Handler: project.json is blank at $pathStr")
                lastSessionFetchTime = now
                return null
            }

            val projectJsonObject = json.parseToJsonElement(text).jsonObject
            val sessionElement = projectJsonObject["sessions"]
            if(sessionElement!=null) {
                val data = json.decodeFromJsonElement<SessionData>(sessionElement)
                lastSessionData = data
                lastSessionFetchTime = now
                lastFileModifiedTime = currentModifiedTime
                return data
            }
            else {
                logger.errorLog("Couldn't parse project.json: session element was missing from\n${projectJsonObject}")
                viewModel?.logError("AI HTTP Handler: 'sessions' element missing in project.json")
                lastSessionFetchTime = now
            }

        }
        catch (e: Exception) {
            logger.errorLog("Couldn't parse project.json: ${e.message}\n${e.stackTrace}")
            viewModel?.logError("AI HTTP Handler: Error parsing project.json: ${e.message}")
            lastSessionFetchTime = now
        }

        return null
    }


}