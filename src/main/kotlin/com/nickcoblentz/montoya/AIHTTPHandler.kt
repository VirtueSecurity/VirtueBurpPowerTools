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
import kotlin.io.path.readText
import kotlin.time.Duration.Companion.seconds

@Serializable
data class SessionData(
    val authenticated: Boolean,
    val cookies: Map<String, String>,
    val headers: Map<String, String>,
)

class AIHTTPHandler(private val api: MontoyaApi, private val myExtensionSettings : MyExtensionSettings) :
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
            return RequestToBeSentAction.continueWith(requestToBeSent)
        }

        var waitCount = 0
        var sessionData = getProjectJsonSession()
        while(sessionData!=null && !sessionData.authenticated && waitCount < 30) {
            waitCount++
            logger.debugLog("Waiting for authentication... ($waitCount/30)")
            Thread.sleep(1.seconds.inWholeMilliseconds)
            sessionData = getProjectJsonSession()
        }

        if(waitCount > 0) {
            logger.warnLog("Total wait time for authentication: $waitCount seconds")
        }

        if(sessionData != null && !sessionData.authenticated && waitCount >= 30) {
            logger.errorLog("Authentication timed out after 30 seconds")
        }

        var httpRequest: HttpRequest = requestToBeSent
        sessionData?.let { data ->
            if (data.authenticated) {
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
        }
        return RequestToBeSentAction.continueWith(httpRequest)
    }

    override fun handleHttpResponseReceived(responseReceived: HttpResponseReceived): ResponseReceivedAction {
        return ResponseReceivedAction.continueWith(responseReceived)
    }

    private fun getProjectJsonSession() : SessionData? {
        val path = Path.of(myExtensionSettings.aiSessionHandlerProjectJSONPath)
        if(!path.exists()) {
            logger.errorLog("Couldn't parse project.json: ${path.toString()} does not exist")
            return null
        }
        val text = path.readText()
        if(text.isBlank()) {
            logger.errorLog("Couldn't parse project.json: ${path.toString()} is blank")
        }

        try {
            val projectJsonObject = json.parseToJsonElement(text).jsonObject
            val sessionElement = projectJsonObject["sessions"]
            if(sessionElement!=null) {
                return json.decodeFromJsonElement<SessionData>(sessionElement)

            }
            else {
                logger.errorLog("Couldn't parse project.json: session element was missing from\n${projectJsonObject}")
            }

        }
        catch (e: Exception) {
            logger.errorLog("Couldn't parse project.json: ${e.message}\n${e.stackTrace}")
        }

        return null
    }


}