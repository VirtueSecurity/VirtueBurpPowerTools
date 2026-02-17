package com.nickcoblentz.montoya

import MyExtensionSettings
import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Annotations
import burp.api.montoya.core.HighlightColor
import burp.api.montoya.core.ToolType
import burp.api.montoya.http.handler.HttpHandler
import burp.api.montoya.http.handler.HttpRequestToBeSent
import burp.api.montoya.http.handler.HttpResponseReceived
import burp.api.montoya.http.handler.RequestToBeSentAction
import burp.api.montoya.http.handler.ResponseReceivedAction
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.isActive
import net.jpountz.xxhash.XXHash64
import net.jpountz.xxhash.XXHashFactory
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap

enum class NotSentToOrganizerReason {
    NOT_UNIQUE,
    NOT_IN_SCOPE,
    TOOL_NOT_ENABLED,
    IGNORE_REGEX,
    WRONG_STATUS_CODE,
    BLANK_RESPONSE,
    MAP_DISABLED
}

class PossibleUniqueItemForOrganizer(val sessionId: String, val request: HttpRequest, val response: HttpResponse, val includeGetParams: Boolean, var requestRegex: String?=null, var responseRegex: String?=null) {
    object Hasher {
        private val factory = XXHashFactory.fastestInstance()
        val hasher: XXHash64 = factory.hash64()
        const val SEED = 0x9747b28c // Any constant long
    }

    private val regexOptions = setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL, RegexOption.MULTILINE)

    val requestCaptureGroups = captureGroupItems(request.toString(),requestRegex)
    val responseCaptureGroups = captureGroupItems(response.toString(),responseRegex)


    fun captureGroupItems(requestOrResponseString : String, regexString : String?) : String {
        regexString?.let {
            if(it.isNotBlank()) {
                val matches = Regex(it,regexOptions)
                    .findAll(requestOrResponseString)
                    .flatMap { it.groupValues.drop(1) }
                    .joinToString(", ")
                if(matches.isNotBlank()) {
                    return matches
                }
            }
        }
        return ""
    }

    fun collectFields() : String {
        return buildList {
            add(sessionId)
            add(request.method().lowercase())
            add(request.httpService().host().lowercase())
            add(request.httpService().port().toString())
            add(request.pathWithoutQuery())
            if(includeGetParams) {
                add(request.query().lowercase())
            }
            if(request.hasHeader("Content-Type")) {
                add(request.header("Content-Type"))
            }
            add(response.statusCode().toString())


            if(requestCaptureGroups.isNotBlank()) {
                add(requestCaptureGroups)
            }


            if(responseCaptureGroups.isNotBlank()) {
                add(responseCaptureGroups)
            }


        }.joinToString("|")
    }

    fun buildHashFromFields() =
        Hasher.hasher.hash(ByteBuffer.wrap(collectFields().toByteArray()),Hasher.SEED)
}

class SendUniqueToOrganizer(private val api: MontoyaApi, private val myExtensionSettings : MyExtensionSettings) : HttpHandler {


    private val logger: MontoyaLogger = MontoyaLogger(api, LogLevel.DEBUG)

    private val exceptionHandler = CoroutineExceptionHandler { _, exception ->
        logger.errorLog("CRITICAL: Uncaught exception in scope: ${exception.message}\n${exception.stackTrace}")
    }

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob() + exceptionHandler)
    private val taskQueue = Channel<HttpResponseReceived>()


    private val pluginName = "Send Unique to Organizer"
    private val regexOptions = setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL, RegexOption.MULTILINE)

    val concurrentSetRequestResponses = ConcurrentHashMap.newKeySet<Long>()

    init {


        logger.debugLog("Started loading the $pluginName extension...")

        api.extension().registerUnloadingHandler {
            logger.debugLog("Unloading the $pluginName extension...")
            taskQueue.close()
            taskQueue.cancel()
            scope.cancel()
        }

        scope.launch {
            while (isActive) {

                    api.organizer().items().filter{ item -> item.annotations().hasNotes() && item.annotations().notes()!=null && item.annotations().notes().contains("Session: ") }.forEach { item ->
                        try {

                            val notes = item.annotations().notes()
                            val pattern = Regex("Session: (\\d)")
                            val results = pattern.find(notes)
                            if(results != null && results.groups.size > 1) {
                                results.groups[1]?.let {


                                    val possibleItem = PossibleUniqueItemForOrganizer(myExtensionSettings.uniqueToOrganizerSelectedSession,
                                        item.request(),
                                        item.response(),
                                        myExtensionSettings.uniqueToOrganizerUniqueQueryParamsOnly,
                                        myExtensionSettings.uniqueToOrganizerRequestUniquenessCaptureGroup,
                                        myExtensionSettings.uniqueToOrganizerResponseUniquenessCaptureGroup)

                                    val hash = possibleItem.buildHashFromFields()
                                    concurrentSetRequestResponses.add(hash)

                                }
                            }
                        } catch (e: Exception) {
                            logger.errorLog("Exception when repopulating hashes:\n${e.message}")
                        }
                    }

            }
        }

        scope.launch {
            for(item in taskQueue) {
                try {
                    processItem(item)
                }
                catch(e: Exception) {
                    logger.errorLog("Exception while processing HttpResponseReceived item:\n${e.message}\n${e.stackTrace}")
                }
            }
        }

        scope.launch {
            while (isActive) {
                delay(30000)
                try {
                    api.organizer().items().filter{ item -> !item.annotations().hasHighlightColor() && item.annotations().hasNotes() && item.annotations().notes()!=null }.forEach { item ->
                        val notes = item.annotations().notes()
                        val pattern = Regex("Session: (\\d)")
                        val results = pattern.find(notes)
                        if(results != null && results.groups.size > 1) {
                            results.groups[1]?.let {
                                logger.debugLog("Trying to set organizer color to ${resolveHighlightColor(it.value).name}")
                                item.annotations().setHighlightColor(resolveHighlightColor(it.value))
                            }
                        }
                    }
                } catch (e: Exception) {
                    logger.errorLog("Exception in Organizer highlight updater coroutine:\n${e.message}")
                }
            }
        }

        api.http().registerHttpHandler(this)

        logger.debugLog("Finished loading the $pluginName extension...")
    }

    private fun processItem(responseReceived: HttpResponseReceived) {

        var modifiedAnnotations = responseReceived.annotations()
        val responseString = responseReceived.toString()
        val request = responseReceived.initiatingRequest()
        val requestString = request.toString()
        val ignoreRegex = Regex(myExtensionSettings.uniqueToOrganizerIgnoreRegexMatch,regexOptions)
        var notSentReason = "None"


        if(myExtensionSettings.uniqueToOrganizerIgnoreRegexMatch.isBlank() ||
           !responseString.matches(ignoreRegex) ||
           !requestString.matches(ignoreRegex)) {

            val possibleItem = PossibleUniqueItemForOrganizer(myExtensionSettings.uniqueToOrganizerSelectedSession,
                request,
                responseReceived,
                myExtensionSettings.uniqueToOrganizerUniqueQueryParamsOnly,
                myExtensionSettings.uniqueToOrganizerRequestUniquenessCaptureGroup,
                myExtensionSettings.uniqueToOrganizerResponseUniquenessCaptureGroup)

            val hash = possibleItem.buildHashFromFields()

            if(!myExtensionSettings.uniqueToOrganizerIncludeUniqueOnly || !concurrentSetRequestResponses.contains(hash)) {

                concurrentSetRequestResponses.add(hash)
                val notes = buildList {
                    if(possibleItem.requestCaptureGroups.isNotBlank()) {
                        add(possibleItem.requestCaptureGroups)
                    }
                    if(possibleItem.responseCaptureGroups.isNotBlank()) {
                        add(possibleItem.responseCaptureGroups)
                    }
                    add("Session: ${possibleItem.sessionId} (${resolveSessionToName()})")
                }
                modifiedAnnotations=Annotations.annotations().withNotes(notes.joinToString("; ")).withHighlightColor(resolveSessionToHighlightColor())
                api.organizer().sendToOrganizer(HttpRequestResponse.httpRequestResponse(request,responseReceived,modifiedAnnotations))

            }
            else {
                notSentReason = NotSentToOrganizerReason.NOT_UNIQUE.name
            }

        }
        else {
            notSentReason=NotSentToOrganizerReason.IGNORE_REGEX.name
        }


        logger.debugLog("Not Sent to Organizer [$notSentReason]: ${request.url()}")
        responseReceived.annotations().setNotes("Not sent to Organizer: $notSentReason")
        responseReceived.annotations().setHighlightColor(HighlightColor.YELLOW)


    }
    fun resolveSessionToHighlightColor() : HighlightColor {
        return resolveHighlightColor(myExtensionSettings.uniqueToOrganizerSelectedSession)
    }

    fun resolveHighlightColor(sessionId : String) : HighlightColor {
        return when(sessionId) {
            "1" -> HighlightColor.MAGENTA
            "2" -> HighlightColor.BLUE
            "3" -> HighlightColor.CYAN
            "4" -> HighlightColor.ORANGE
            "5" -> HighlightColor.YELLOW
            "6" -> HighlightColor.PINK
            else -> HighlightColor.NONE
        }
    }

    fun resolveSessionToName() : String {
        return when(myExtensionSettings.uniqueToOrganizerSelectedSession) {
            "1" -> myExtensionSettings.uniqueToOrganizerSession1Name
            "2" -> myExtensionSettings.uniqueToOrganizerSession2Name
            "3" -> myExtensionSettings.uniqueToOrganizerSession3Name
            "4" -> myExtensionSettings.uniqueToOrganizerSession4Name
            "5" -> myExtensionSettings.uniqueToOrganizerSession5Name
            "6" -> myExtensionSettings.uniqueToOrganizerSession6Name
            else -> "Error, Unknown (${myExtensionSettings.uniqueToOrganizerSelectedSession})"
        }
    }

    override fun handleHttpRequestToBeSent(requestToBeSent: HttpRequestToBeSent?): RequestToBeSentAction? {
        return RequestToBeSentAction.continueWith(requestToBeSent)
    }

    override fun handleHttpResponseReceived(responseReceived: HttpResponseReceived?): ResponseReceivedAction? {

        if(myExtensionSettings.uniqueToOrganizerMapEnabled) {
            responseReceived?.let { responseReceived ->

                var modifiedAnnotations = responseReceived.annotations()
                val request = responseReceived.initiatingRequest()
                if(request.isInScope) {
                    val toolSource = responseReceived.toolSource()
                    if(myExtensionSettings.uniqueToOrganizerMapEnabled) {
                      if((toolSource.isFromTool(ToolType.PROXY) && myExtensionSettings.uniqueToOrganizerProxyMapEnabled) ||
                          (toolSource.isFromTool(ToolType.INTRUDER) && myExtensionSettings.uniqueToOrganizerIntruderMapEnabled) ||
                          (toolSource.isFromTool(ToolType.REPEATER) && myExtensionSettings.uniqueToOrganizerRepeaterMapEnabled) ||
                          (toolSource.isFromTool(ToolType.EXTENSIONS) && myExtensionSettings.uniqueToOrganizerExtensionMapEnabled)
                          ) {

                          if(statusCodeMatches(responseReceived.statusCode())) {
                              scope.launch {
                                  taskQueue.send(responseReceived)
                              }
                          }
                          else {
                              modifiedAnnotations = labelNotSentToOrganizer(responseReceived, NotSentToOrganizerReason.WRONG_STATUS_CODE)
                          }
                      }
                      else {
                          modifiedAnnotations = labelNotSentToOrganizer(responseReceived, NotSentToOrganizerReason.TOOL_NOT_ENABLED)
                      }


                    }
                    else {
                        modifiedAnnotations = labelNotSentToOrganizer(responseReceived, NotSentToOrganizerReason.MAP_DISABLED)
                    }
                }
                else {
                    modifiedAnnotations = labelNotSentToOrganizer(responseReceived, NotSentToOrganizerReason.NOT_IN_SCOPE)
                }
                return ResponseReceivedAction.continueWith(responseReceived, modifiedAnnotations)
            }
        }

        return ResponseReceivedAction.continueWith(responseReceived)
    }

    private fun labelNotSentToOrganizer(responseReceived: HttpResponseReceived, reason: NotSentToOrganizerReason) : Annotations {

        val comment = listOf(responseReceived.annotations().notes(),"Not Sent to Organizer: ${reason.name}")
            .filterNot {  it.isNullOrBlank()}.joinToString(",")

        val highlightColor = if(reason in listOf(NotSentToOrganizerReason.NOT_IN_SCOPE, NotSentToOrganizerReason.MAP_DISABLED, NotSentToOrganizerReason.BLANK_RESPONSE)) {
            HighlightColor.NONE
        }
        else {
            HighlightColor.YELLOW
        }

        return responseReceived.annotations().withNotes(comment).withHighlightColor(highlightColor)
    }

    private fun statusCodeMatches(statusCode : Short) : Boolean {

        val allowedConfig = myExtensionSettings.uniqueToOrganizerStatusCodes

        val isAllowed = allowedConfig.split(",").any { part ->
            if (part.contains("-")) {
                val (start, end) = part.split("-").map { it.trim().toShort() }
                statusCode in start..end
            } else {
                part.trim().toShortOrNull() == statusCode
            }
        }

        return isAllowed
    }
}
