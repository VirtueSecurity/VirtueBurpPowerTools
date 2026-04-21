import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.sessions.ActionResult
import burp.api.montoya.http.sessions.SessionHandlingAction
import burp.api.montoya.http.sessions.SessionHandlingActionData
import com.nickcoblentz.montoya.LogLevel
import com.nickcoblentz.montoya.MontoyaLogger
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.ui.contextmenu.AuditIssueContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse
import burp.api.montoya.ui.contextmenu.WebSocketContextMenuEvent
import burp.api.montoya.ui.settings.SettingsPanelBuilder
import burp.api.montoya.ui.settings.SettingsPanelPersistence
import com.nickcoblentz.montoya.settings.PanelSettingsDelegate
import com.nickcoblentz.montoya.withUpdatedContentLength
import java.awt.Component
import java.awt.Font
import java.util.Optional
import javax.swing.JLabel
import javax.swing.JMenuItem
import javax.swing.JSeparator
import kotlin.text.Regex


class MatchReplaceSessionExtension(private val api: MontoyaApi, private val myExtensionSettings : MyExtensionSettings) : SessionHandlingAction,ContextMenuItemsProvider {



    private lateinit var logger: MontoyaLogger

    private val testJMenu = JMenuItem("Test It")
    private lateinit var messageEditorRequestResponse: Optional<MessageEditorHttpRequestResponse>
    private lateinit var selectedRequestResponses: MutableList<HttpRequestResponse>



    private val pluginName = "Match/Replace Session"
    private val regexOptions = setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL, RegexOption.MULTILINE)

    private val label = JLabel("  Replace Session").apply {
        isEnabled = false
        font = font.deriveFont(Font.BOLD)
    }

    private val menuItems : List<Component> = listOf(label, testJMenu,JSeparator())

    init {

        logger = MontoyaLogger(api, LogLevel.DEBUG)
        logger.debugLog("Started loading the Match Replace Session extension...")


        api.http().registerSessionHandlingAction(this)

        api.userInterface().registerContextMenuItemsProvider(this)

        testJMenu.addActionListener {actionEvent ->
            val requests = mutableListOf<HttpRequest>()
            messageEditorRequestResponse.ifPresent { requestResponse ->
                requests.add(requestResponse.requestResponse().request())
            }
            if(selectedRequestResponses.isNotEmpty()) {
                requests.addAll(selectedRequestResponses.map { it.request() })
            }

//            requests.forEach { request ->
//                api.logging().logToOutput("=================${request.url()}=================")
//                api.logging().logToOutput(doMatchReplace(request.toString()))
//                api.logging().logToOutput("--------------------------------------------------")
//            }


        }


        // See logging comment above
        logger.debugLog("...Finished loading the Match Replace Session extension")

    }

    override fun name() = pluginName

    override fun performAction(actionData: SessionHandlingActionData?): ActionResult? {
        actionData?.request()?.let {
            return ActionResult.actionResult(HttpRequest.httpRequest(it.httpService(),doMatchReplace(it.toString())).withUpdatedContentLength())
        }
        return ActionResult.actionResult(null)
    }

    private var cachedRegexOne: Pair<String, Regex>? = null
    private var cachedRegexTwo: Pair<String, Regex>? = null
    private var cachedRegexThree: Pair<String, Regex>? = null

    private fun getRegexOne(): Regex? {
        val pattern = myExtensionSettings.matchOneSetting
        if (pattern.isBlank()) return null
        if (cachedRegexOne?.first != pattern) {
            cachedRegexOne = pattern to Regex(pattern, regexOptions)
        }
        return cachedRegexOne?.second
    }

    private fun getRegexTwo(): Regex? {
        val pattern = myExtensionSettings.matchTwoSetting
        if (pattern.isBlank()) return null
        if (cachedRegexTwo?.first != pattern) {
            cachedRegexTwo = pattern to Regex(pattern, regexOptions)
        }
        return cachedRegexTwo?.second
    }

    private fun getRegexThree(): Regex? {
        val pattern = myExtensionSettings.matchThreeSetting
        if (pattern.isBlank()) return null
        if (cachedRegexThree?.first != pattern) {
            cachedRegexThree = pattern to Regex(pattern, regexOptions)
        }
        return cachedRegexThree?.second
    }

    private fun doMatchReplace(requestInputString: String): String {

//        logger.debugLog("Found:\n$requestInputString")

        var newString = requestInputString
        getRegexOne()?.let { newString = it.replace(newString, myExtensionSettings.replaceOneSetting) }
        getRegexTwo()?.let { newString = it.replace(newString, myExtensionSettings.replaceTwoSetting) }
        getRegexThree()?.let { newString = it.replace(newString, myExtensionSettings.replaceThreeSetting) }

//        logger.debugLog("Result: $newString")
        return newString

    }

    override fun provideMenuItems(event: ContextMenuEvent?): List<Component?>? {
        event?.let {
            if(it.selectedRequestResponses().isNotEmpty() || !it.messageEditorRequestResponse().isEmpty) {
                selectedRequestResponses = it.selectedRequestResponses()
                messageEditorRequestResponse = it.messageEditorRequestResponse()
                return menuItems
            }
        }
        return super.provideMenuItems(event)
    }

    override fun provideMenuItems(event: WebSocketContextMenuEvent?): List<Component?>? {
        return super.provideMenuItems(event)
    }

    override fun provideMenuItems(event: AuditIssueContextMenuEvent?): List<Component?>? {
        return super.provideMenuItems(event)
    }


}

private fun wrapText(text: String, width: Int = 120): String {
    val regex = Regex("(.{1,$width})(?:\\s+|\\$\\n?)|(.{1,$width})")
    return text.replace(regex, "$1$2\n")
}


//testInputSetting = StringExtensionSetting(
//// pass the montoya API to the setting
//api,
//// Give the setting a name which will show up in the Swing UI Form
//"Test Input Box",
//// Key for where to save this setting in Burp's persistence store
//"MatchReplace.input",
//// Default value within the Swing UI Form
//"",
//// Whether to save it for this specific "PROJECT" or as a global Burp "PREFERENCE"
//ExtensionSettingSaveLocation.PROJECT
//)

//class MyExtensionSettings {
//    val settingsPanelBuilder : SettingsPanelBuilder = SettingsPanelBuilder.settingsPanel()
//        .withPersistence(SettingsPanelPersistence.PROJECT_SETTINGS)
//        .withTitle("Match/Replace")
//        .withDescription("Update Settings")
//        .withKeywords("Match","Replace")
//
//    private val settingsManager = PanelSettingsDelegate(settingsPanelBuilder)
//
//    val matchOneSetting: String by settingsManager.stringSetting("First Match Expression", "")
//    val replaceOneSetting: String by settingsManager.stringSetting("First Replace Expression", "")
//
//    val matchTwoSetting: String by settingsManager.stringSetting("Second Match Expression", "")
//    val replaceTwoSetting: String by settingsManager.stringSetting("Second Replace Expression", "")
//
//    val matchThreeSetting: String by settingsManager.stringSetting("Third Match Expression", "")
//    val replaceThreeSetting: String by settingsManager.stringSetting("Third Replace Expression", "")
//
//
//
//
//    val settingsPanel = settingsManager.buildSettingsPanel()
//
//
//}
