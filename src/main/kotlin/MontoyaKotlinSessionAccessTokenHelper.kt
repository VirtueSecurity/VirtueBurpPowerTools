import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.handler.*
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.sessions.ActionResult
import burp.api.montoya.http.sessions.SessionHandlingAction
import burp.api.montoya.http.sessions.SessionHandlingActionData
import burp.api.montoya.ui.contextmenu.AuditIssueContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse
import burp.api.montoya.ui.contextmenu.WebSocketContextMenuEvent
import burp.api.montoya.ui.settings.SettingsPanelBuilder
import burp.api.montoya.ui.settings.SettingsPanelPersistence
import burp.api.montoya.ui.settings.SettingsPanelSetting
import burp.api.montoya.ui.settings.SettingsPanelWithData
import com.nickcoblentz.montoya.LogLevel
import com.nickcoblentz.montoya.MontoyaLogger
import java.awt.Component
import java.util.Optional
import java.util.regex.Pattern
import javax.swing.JMenuItem
import kotlin.properties.ReadOnlyProperty


class MontoyaKotlinSessionAccessTokenHelper(private val api : MontoyaApi, private val myExtensionSettings: MyExtensionSettings) : SessionHandlingAction, ContextMenuItemsProvider, HttpHandler {

    private lateinit var messageEditorRequestResponse: Optional<MessageEditorHttpRequestResponse>
    private lateinit var selectedRequestResponses: MutableList<HttpRequestResponse>
    private var accessToken = ""
    private var logger: MontoyaLogger = MontoyaLogger(api, LogLevel.DEBUG)

    private val testJMenu = JMenuItem("Test It")



    companion object {
        const val PLUGIN_NAME: String = "Session Handling: Access Token Helper"

    }

    init {


        logger.debugLog( "Plugin $PLUGIN_NAME Starting...")

        api.http().registerSessionHandlingAction(this)

        api.userInterface().registerContextMenuItemsProvider(this)

        api.http().registerHttpHandler(this)

        testJMenu.addActionListener {actionEvent ->
            val requests = mutableListOf<HttpRequest>()
            messageEditorRequestResponse.ifPresent { requestResponse ->
                requests.add(requestResponse.requestResponse().request())
            }
            if(selectedRequestResponses.isNotEmpty()) {
                requests.addAll(selectedRequestResponses.map { it.request() })
            }

            requests.forEach { request ->
                api.logging().logToOutput("=================${request.url()}=================")
                api.logging().logToOutput(updateRequestWithAccessToken(request).toString())
                api.logging().logToOutput("--------------------------------------------------")
            }


        }
        logger.debugLog("$PLUGIN_NAME Finished")


    }

    override fun name(): String {
        return PLUGIN_NAME
    }

    override fun performAction(actionData: SessionHandlingActionData): ActionResult {
        logger.debugLog(this.javaClass.name, "=======================\nperformAction")
        var request = actionData.request()

        logger.debugLog("---------------------------\nStage 1: Checking for Macros")
        if(actionData.macroRequestResponses().isNotEmpty()) {
            logger.debugLog("Found Macro Request/Response")
            for (httpReqRes in actionData.macroRequestResponses()) {
                if(httpReqRes.hasResponse())
                    updateAccessTokenIfFound(httpReqRes.response().toString())
            }
        }
        else
            logger.debugLog("No macro found")

        logger.debugLog("------------------------\nStage 2: Session Handling")

        request = updateRequestWithAccessToken(request)

        logger.debugLog("Done, returning")
        return ActionResult.actionResult(request, actionData.annotations())
    }

    fun updateRequestWithAccessToken(request: HttpRequest) : HttpRequest {
        var newRequest = request
        logger.debugLog("updating with access token: $accessToken")
        if (accessToken.isNotEmpty() && !urlShouldBeIgnored(newRequest)) {
            logger.debugLog("Access token non-empty: ${accessToken}, valid URL (not ignore url): ${newRequest.url()}")
            if(myExtensionSettings.headerName1Setting.isNotBlank()) {
                logger.debugLog("Access Token and Header1 Not Empty, adding header: ${myExtensionSettings.headerName1Setting}: ${previewHeaderValue()}")
                newRequest = if (newRequest.hasHeader(myExtensionSettings.headerName1Setting))
                    newRequest.withUpdatedHeader(myExtensionSettings.headerName1Setting, previewHeaderValue())
                else
                    newRequest.withAddedHeader(myExtensionSettings.headerName1Setting, previewHeaderValue())
            }
            else
                logger.debugLog("Skipping ${myExtensionSettings.headerName1Setting} header, empty")

            if(myExtensionSettings.headerName2Setting.isNotBlank()) {
                logger.debugLog("Access Token and Header2 Not Empty, adding header: ${myExtensionSettings.headerName2Setting}: ${previewHeaderValue()}")
                newRequest = if (newRequest.hasHeader(myExtensionSettings.headerName2Setting))
                    newRequest.withUpdatedHeader(myExtensionSettings.headerName2Setting, previewHeaderValue(true))
                else
                    newRequest.withAddedHeader(myExtensionSettings.headerName2Setting, previewHeaderValue(true))
            }
            else
                logger.debugLog("Skipping ${myExtensionSettings.headerName2Setting} header, empty")
        }
        return newRequest
    }

    fun urlShouldBeIgnored(request: HttpRequest) : Boolean {
        return myExtensionSettings.shouldIgnoreEndpointsSetting
                && myExtensionSettings.ignoreEndpointsSetting.isNotBlank()
                && myExtensionSettings.ignoreEndpointsSetting.toRegex().containsMatchIn(request.url())
    }

    fun updateAccessTokenIfFound(responseString: String)
    {
        //Logger.debugLog("response string:\n$responseString")
        val pattern = Pattern.compile(myExtensionSettings.accessTokenPatternSetting, Pattern.CASE_INSENSITIVE)
        val matcher = pattern.matcher(responseString)
        while (matcher.find() && matcher.groupCount() > 0) {
            accessToken = matcher.group(1)
            logger.debugLog("Found Access Token: $accessToken")
        }
    }

    private fun previewHeaderValue(secondHeader : Boolean = false) : String {
        val headerBuilder = StringBuilder()
        if(secondHeader) {
            headerBuilder.append(myExtensionSettings.headerValuePrefix2Setting)
            if(accessToken.isEmpty())
                headerBuilder.append("ACCESS TOKEN HERE")
            else
                headerBuilder.append(accessToken)
            headerBuilder.append(myExtensionSettings.headerValueSuffix2Setting)
        }
        else {
            headerBuilder.append(myExtensionSettings.headerValuePrefix1Setting)
            if(accessToken.isEmpty())
                headerBuilder.append("ACCESS TOKEN HERE")
            else
                headerBuilder.append(accessToken)
            headerBuilder.append(myExtensionSettings.headerValueSuffix1Setting)
        }

        return headerBuilder.toString()
    }

    override fun handleHttpRequestToBeSent(requestToBeSent: HttpRequestToBeSent?): RequestToBeSentAction {
        return RequestToBeSentAction.continueWith(requestToBeSent)
    }

    override fun handleHttpResponseReceived(responseReceived: HttpResponseReceived?): ResponseReceivedAction {
        if(myExtensionSettings.passiveSetting)
            responseReceived?.let {
                updateAccessTokenIfFound(it.toString())
            }
        return ResponseReceivedAction.continueWith(responseReceived)
    }

    override fun provideMenuItems(event: ContextMenuEvent?): List<Component?>? {
        event?.let {
            if(it.selectedRequestResponses().isNotEmpty() || !it.messageEditorRequestResponse().isEmpty) {
                selectedRequestResponses = it.selectedRequestResponses()
                messageEditorRequestResponse = it.messageEditorRequestResponse()
                return listOf(testJMenu)
            }
        }
        return super.provideMenuItems(event)
    }

}

class SettingsDelegateManager(private var settingsPanelBuilder : SettingsPanelBuilder) {

    var settingsPanel : SettingsPanelWithData? = null

    fun stringSetting(name: String, defaultValue: String): ReadOnlyProperty<Any, String> {
        settingsPanelBuilder.withSetting(SettingsPanelSetting.stringSetting(name, defaultValue))

        // This delegate will call the provider to get the panel only when the property is accessed.
        return ReadOnlyProperty { _, _ -> settingsPanel?.getString(name) ?: "" }
    }

    /**
     * Creates and registers a Boolean setting delegate.
     */
    fun booleanSetting(name: String, defaultValue: Boolean): ReadOnlyProperty<Any, Boolean> {
        settingsPanelBuilder.withSetting(SettingsPanelSetting.booleanSetting(name, defaultValue))
        return ReadOnlyProperty { _, _ -> settingsPanel?.getBoolean(name) ?: false}
    }

    fun buildSettingsPanel() : SettingsPanelWithData {
        val settingsPanelTemp = settingsPanelBuilder.build()
        settingsPanel = settingsPanelTemp
        return settingsPanelTemp
    }
}


//class MyExtensionSettings {
//    val settingsPanelBuilder : SettingsPanelBuilder = SettingsPanelBuilder.settingsPanel()
//        .withPersistence(SettingsPanelPersistence.PROJECT_SETTINGS)
//        .withTitle("Session Token Helper")
//        .withDescription("Configure the session handling settings.")
//        .withKeywords("Session", "JWT", "Authorization", "Token", "Macro")
//
//    private val settingsManager = SettingsDelegateManager(settingsPanelBuilder)
//
//    val accessTokenPatternSetting: String by settingsManager.stringSetting("Access Token RegEx Pattern", "\"access_token\" *: *\"([^\"]+)\"")
//    val headerName1Setting: String by settingsManager.stringSetting("Header Name 1", "Authorization")
//    val headerValuePrefix1Setting: String by settingsManager.stringSetting("Header Value Prefix 1", "Bearer ")
//    val headerValueSuffix1Setting: String by settingsManager.stringSetting("Header Value Suffix 1", "")
//    val headerName2Setting: String by settingsManager.stringSetting("Header Name 2", "")
//    val headerValuePrefix2Setting: String by settingsManager.stringSetting("Header Value Prefix 2", "")
//    val headerValueSuffix2Setting: String by settingsManager.stringSetting("Header Value Suffix 2", "")
//    val ignoreEndpointsSetting: String by settingsManager.stringSetting("Regex of URLs to Ignore when applying the token", "")
//
//    val passiveSetting: Boolean by settingsManager.booleanSetting("Use Passively For All Requests?", false)
//    val shouldIgnoreEndpointsSetting: Boolean by settingsManager.booleanSetting("Should Ignore Endpoints?", false)
//
//    val settingsPanel = settingsManager.buildSettingsPanel()
//}
