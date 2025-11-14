//import burp.api.montoya.MontoyaApi
//import burp.api.montoya.http.handler.HttpHandler
//import burp.api.montoya.http.handler.HttpRequestToBeSent
//import burp.api.montoya.http.handler.HttpResponseReceived
//import burp.api.montoya.http.handler.RequestToBeSentAction
//import burp.api.montoya.http.handler.ResponseReceivedAction
//import burp.api.montoya.http.message.requests.HttpRequest
//import burp.api.montoya.http.message.responses.HttpResponse
//import burp.api.montoya.http.sessions.ActionResult
//import burp.api.montoya.http.sessions.SessionHandlingAction
//import burp.api.montoya.http.sessions.SessionHandlingActionData
//import com.nickcoblentz.montoya.LogLevel
//import com.nickcoblentz.montoya.MontoyaLogger
//import com.nickcoblentz.montoya.withUpdatedContentLength
//
//class VariableExtractInjectExtension(private val api: MontoyaApi, private val myExtensionSettings: MyExtensionSettings) : HttpHandler, SessionHandlingAction {
//    private var variable1value=""
//    private var variable2value=""
//    private var variable3value=""
//    private var variable4value=""
//
//    private var logger: MontoyaLogger = MontoyaLogger(api, LogLevel.DEBUG)
//
//    init {
//        logger.debugLog("Started loading the Variable Extract Inject Extension...")
//        api.http().registerHttpHandler(this)
//        api.http().registerSessionHandlingAction(this)
//        logger.debugLog("Finished loading the Variable Extract Inject Extension...")
//    }
//
//    override fun handleHttpRequestToBeSent(httpRequest: HttpRequestToBeSent?): RequestToBeSentAction? {
//        if(httpRequest?.isInScope ?: false) {
//            extractVariables(httpRequest.toString())
//        }
//        return RequestToBeSentAction.continueWith(httpRequest)
//    }
//
//    override fun handleHttpResponseReceived(httpResponse: HttpResponseReceived?): ResponseReceivedAction? {
//        if(httpResponse?.initiatingRequest()?.isInScope ?: false) {
//            extractVariables(httpResponse.toString())
//        }
//        return ResponseReceivedAction.continueWith(httpResponse)
//    }
//
//    private fun extractVariables(data: String) {
//        extractAndAssignVariable(
//            data = data,
//            searchEnabled = myExtensionSettings.varExtInjVar1SearchEnabled,
//            regexString = myExtensionSettings.varExtInjVar1Search,
//            onMatch = { value -> variable1value = value }
//        )
//
//        extractAndAssignVariable(
//            data = data,
//            searchEnabled = myExtensionSettings.varExtInjVar2SearchEnabled,
//            regexString = myExtensionSettings.varExtInjVar2Search,
//            onMatch = { value -> variable2value = value }
//        )
//
//        extractAndAssignVariable(
//            data = data,
//            searchEnabled = myExtensionSettings.varExtInjVar3SearchEnabled,
//            regexString = myExtensionSettings.varExtInjVar3Search,
//            onMatch = { value -> variable3value = value }
//        )
//
//        extractAndAssignVariable(
//            data = data,
//            searchEnabled = myExtensionSettings.varExtInjVar4SearchEnabled,
//            regexString = myExtensionSettings.varExtInjVar4Search,
//            onMatch = { value -> variable4value = value }
//        )
//    }
//
//    private fun extractAndAssignVariable(
//        data : String,
//        searchEnabled: Boolean,
//        regexString: String,
//        onMatch: (String) -> Unit
//    ) {
//        if (searchEnabled) {
//            val matchResult = regexString.toRegex(setOf(RegexOption.MULTILINE, RegexOption.IGNORE_CASE)).find(data)
//            val extractedValue = matchResult?.groupValues?.getOrNull(1)
//            if (extractedValue != null) {
//                logger.debugLog("$regexString found $extractedValue")
//                onMatch(extractedValue)
//            }
//        }
//    }
//
//
//
//
//    override fun name(): String = "VariableExtractInjectSessionAction"
//
//    private fun replaceVariables(data : String) : String {
//        return data
//            .replace("{{variable1}}",variable1value)
//            .replace("{{variable2}}",variable2value)
//            .replace("{{variable3}}",variable3value)
//            .replace("{{variable4}}",variable4value)
//    }
//
//    override fun performAction(actionData: SessionHandlingActionData): ActionResult {
//        val httpRequest = actionData.request()
//        var httpRequestString = httpRequest.toString()
//
//        if(myExtensionSettings.varExtInjReplaceEnabled1) {
//            httpRequestString=httpRequestString.replace(
//                myExtensionSettings.varExtInjSearch1
//                .toRegex(setOf(RegexOption.MULTILINE, RegexOption.IGNORE_CASE)),
//                replaceVariables(myExtensionSettings.varExtInjReplace1))
//        }
//
//        if(myExtensionSettings.varExtInjReplaceEnabled2) {
//            httpRequestString=httpRequestString.replace(
//                myExtensionSettings.varExtInjSearch2
//                    .toRegex(setOf(RegexOption.MULTILINE, RegexOption.IGNORE_CASE)),
//                replaceVariables(myExtensionSettings.varExtInjReplace2))
//        }
//
//        if(myExtensionSettings.varExtInjReplaceEnabled3) {
//            httpRequestString=httpRequestString.replace(
//                myExtensionSettings.varExtInjSearch3
//                    .toRegex(setOf(RegexOption.MULTILINE, RegexOption.IGNORE_CASE)),
//                replaceVariables(myExtensionSettings.varExtInjReplace3))
//        }
//
//        if(myExtensionSettings.varExtInjReplaceEnabled4) {
//            httpRequestString=httpRequestString.replace(
//                myExtensionSettings.varExtInjSearch4
//                    .toRegex(setOf(RegexOption.MULTILINE, RegexOption.IGNORE_CASE)),
//                replaceVariables(myExtensionSettings.varExtInjReplace4))
//        }
//
//        return ActionResult.actionResult(HttpRequest.httpRequest(httpRequest.httpService(),httpRequestString).withUpdatedContentLength())
//    }
//}