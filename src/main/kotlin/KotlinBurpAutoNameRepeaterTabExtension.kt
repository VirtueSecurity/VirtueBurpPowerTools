import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.ui.contextmenu.AuditIssueContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider
import burp.api.montoya.ui.contextmenu.WebSocketContextMenuEvent
import com.nickcoblentz.montoya.LogLevel
import com.nickcoblentz.montoya.MontoyaLogger
import java.awt.Component
import javax.swing.JMenuItem
import burp.api.montoya.core.Annotations
import com.nickcoblentz.montoya.EveryParameter2
import java.awt.Font
import javax.swing.JLabel
import javax.swing.JSeparator


// Montoya API Documentation: https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/MontoyaApi.html
// Montoya Extension Examples: https://github.com/PortSwigger/burp-extensions-montoya-api-examples

class KotlinBurpAutoNameRepeaterTabExtension(private val api: MontoyaApi, private val myExtensionSettings: MyExtensionSettings) : ContextMenuItemsProvider {

    private var logger: MontoyaLogger = MontoyaLogger(api, LogLevel.DEBUG)
    private val sendToRepeaterMenuItem = JMenuItem("Send To Repeater & Auto Name")
    private val sendToOrganizerUniqueMenuItem = JMenuItem("Send Unique To Organizer")
    private val sendToOrganizerUniqueVerbURLMenuItem = JMenuItem("Send Unique Verb/URL To Organizer")
    private val sendToOrganizerUniqueVerbHostPathMenuItem = JMenuItem("Send Unique Verb/Host/Path To Organizer")
    private val sendToOrganizerUniqueHostPathMenuItem = JMenuItem("Send Unique Host/Path To Organizer")

    private val includeBaseURLInScopeMenuItem = JMenuItem("Add Base URL to Scope")
    private val excludeBaseURLFromScopeMenuItem = JMenuItem("Exclude Base URL from Scope")
    private var requestResponses = emptyList<HttpRequestResponse>()
//    private var organizerCounter = 0

    private val label = JLabel("  AutoName").apply {
        isEnabled = false
        font = font.deriveFont(Font.BOLD)
    }

    private val menuItems : MutableList<Component> = mutableListOf(label,sendToRepeaterMenuItem, sendToOrganizerUniqueMenuItem,sendToOrganizerUniqueHostPathMenuItem,sendToOrganizerUniqueVerbHostPathMenuItem, sendToOrganizerUniqueVerbURLMenuItem,includeBaseURLInScopeMenuItem, excludeBaseURLFromScopeMenuItem,JSeparator())

    // Uncomment this section if you wish to use persistent settings and automatic UI Generation from: https://github.com/ncoblentz/BurpMontoyaLibrary
    // Add one or more persistent settings here
    // private lateinit var exampleNameSetting : StringExtensionSetting

    init {

        // This will print to Burp Suite's Extension output and can be used to debug whether the extension loaded properly
        logger.debugLog("Started loading the AutoNameRepeater extension...")



//        api.extension().setName("Auto Name Repeater Tab")


        // Just a simple hello world to start with
        api.userInterface().registerContextMenuItemsProvider(this)
        sendToRepeaterMenuItem.addActionListener {_ -> sendToRepeater() }
        sendToOrganizerUniqueVerbHostPathMenuItem.addActionListener { _ -> sendToOrganizer(SendToOrganizerOption.UNIQUE_METHOD_PATH) }
        sendToOrganizerUniqueVerbURLMenuItem.addActionListener { _ -> sendToOrganizer(SendToOrganizerOption.UNIQUE_METHOD_URL) }
        sendToOrganizerUniqueHostPathMenuItem.addActionListener { _ -> sendToOrganizer(SendToOrganizerOption.UNIQUE_PATH) }
        sendToOrganizerUniqueMenuItem.addActionListener { _ -> sendToOrganizer(SendToOrganizerOption.NONE) }
        includeBaseURLInScopeMenuItem.addActionListener  { _ -> includeInScope() }
        excludeBaseURLFromScopeMenuItem.addActionListener  {_ -> excludeFromScope() }

        // Code for setting up your extension ends here

        // See logging comment above
        logger.debugLog("...Finished loading the AutoNameRepeater extension")

    }

    enum class SendToOrganizerOption {
        NONE,
        UNIQUE_METHOD_URL,
        UNIQUE_METHOD_PATH,
        UNIQUE_PATH
    }

    private fun includeInScope() {
        if(requestResponses.isNotEmpty()) {
            for(requestResponse in requestResponses) {
                val url = getBaseURL(requestResponse)
                api.logging().logToOutput(requestResponse.request().url())
                api.logging().logToOutput(url)
                api.scope().includeInScope(url);
            }
        }
    }

    private fun excludeFromScope() {
        if(requestResponses.isNotEmpty()) {
            for(requestResponse in requestResponses) {
                val url = getBaseURL(requestResponse)
                api.logging().logToOutput(url)
                api.scope().excludeFromScope(url)
            }
        }
    }

    private fun getBaseURL(requestResponse: HttpRequestResponse) : String = requestResponse.request().url().replace(requestResponse.request().path().substring(1),"")

    private fun sendToOrganizer(option : SendToOrganizerOption) {
        if(requestResponses.isNotEmpty()) {
//            if(myExtensionSettings.tagGroupsInOrganizerNotesSetting && requestResponses.size>1) {
//                organizerCounter++
//            }

            val groupedRequestResponses = when (option) {
                SendToOrganizerOption.UNIQUE_METHOD_PATH -> requestResponses.groupBy {
                    "${it.request().method()} ${
                        it.request().pathWithoutQuery()
                    }".lowercase()
                }

                SendToOrganizerOption.UNIQUE_METHOD_URL -> requestResponses.groupBy {
                    "${it.request().method()} ${
                        it.request().url()
                    }".lowercase()
                }

                SendToOrganizerOption.UNIQUE_PATH -> requestResponses.groupBy {
                    it.request().pathWithoutQuery().lowercase()
                }

                SendToOrganizerOption.NONE -> mapOf("none" to requestResponses)
            }

            groupedRequestResponses.forEach { (groupName, rqRs) ->
                logger.debugLog("Working on group: $groupName")
                Thread.ofVirtual().start {
                    logger.debugLog("Ranking...")
                    val rankedRequests = api.utilities().rankingUtils().rank(rqRs)
                    val uniqueRankedRequests = rankedRequests.distinctBy { it.rank() }
                    uniqueRankedRequests.forEach {
                        val rqRs = enrichWithTestCaseNotes(it.requestResponse().withAnnotations(Annotations.annotations("Rank: ${it.rank()}")))

                        api.organizer().sendToOrganizer(rqRs)
                    }
                }
            }
        }
    }

//            for(requestResponse in requestResponses) {
//                val annotationNotesBuilder = buildString {
//                    append(myExtensionSettings.prependStringToOrganizerNotesSetting+" ")
//                    if(myExtensionSettings.tagGroupsInOrganizerNotesSetting && requestResponses.size>1) {
//                        append(" $organizerCounter ")
//                    }
//                    if(myExtensionSettings.useTitleInOrganizerNotesSetting && requestResponse.hasResponse()) {
//                        val body = requestResponse.response().bodyToString()
//                        val titleStartString = "<title>"
//                        val titleStartIndex = body.indexOf(titleStartString)
//                        val titleEndIndex = body.indexOf("</title>")
//                        val headStartIndex = body.indexOf("<head>")
//                        val headEndIndex = body.indexOf("</head>")
//                        if(titleStartIndex != -1 && titleEndIndex != -1 && headStartIndex != -1 && headEndIndex != -1 &&
//                            titleStartIndex > headStartIndex && titleEndIndex < headEndIndex) {
//                            append(" "+body.substring(titleStartIndex+titleStartString.length,titleEndIndex)+" ")
//                        }
//                    }
//                    append(" "+myExtensionSettings.appendStringToOrganizerNotesSetting)
//                }

//                val highlightColor = HighlightColor.valueOf(myExtensionSettings.highlightColorForOrganizerSetting)

//
//                api.organizer().sendToOrganizer(requestResponse.withAnnotations(Annotations.annotations(annotationNotesBuilder.toString(),highlightColor)))
//            }
//        }
//    }

    private fun enrichWithTestCaseNotes(requestResponse : HttpRequestResponse) : HttpRequestResponse {
        val request = requestResponse.request()
        if(EveryParameter2.requestHasTestCaseFields(request)) {
            val originalNotes = requestResponse.annotations().notes()
            val appendNotes = "${EveryParameter2.extractTestCaseFieldFromRequest(EveryParameter2.testCaseCategoryHeader,request)} - " +
                    "${EveryParameter2.extractTestCaseFieldFromRequest(EveryParameter2.testCaseNameHeader,request)}: " +
                    EveryParameter2.extractTestCaseFieldFromRequest(EveryParameter2.testCasePayloadHeader,request)
            return if(originalNotes.isBlank()) {
                requestResponse.withAnnotations(Annotations.annotations(appendNotes))
            } else {
                requestResponse.withAnnotations(Annotations.annotations("$originalNotes $appendNotes"))
            }
        }

        return requestResponse
    }

    private fun sendToRepeater() {
        if(requestResponses.isNotEmpty()) {
            for(requestResponse in requestResponses) {
                api.repeater().sendToRepeater(requestResponse.request(),extractTabNameFromRequest(requestResponse.request()))
            }
        }
    }

    private fun extractTabNameFromRequest(request : HttpRequest) : String {
        return buildString {
            append(request.method()+" ")
            append(request.pathWithoutQuery()
                .replace("/[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}".toRegex(RegexOption.IGNORE_CASE),"/:uuid")
                .replace("/api/","/")
                .replace("/\\d+".toRegex(),"/:num")
                .replace("/v\\d/".toRegex(),"/")
                )
        }
    }

    override fun provideMenuItems(event: ContextMenuEvent?): MutableList<Component> {
        event?.let {
            requestResponses = if(it.selectedRequestResponses().isNotEmpty()) {
                it.selectedRequestResponses()
            }
            else if(!it.messageEditorRequestResponse().isEmpty) {
                listOf(it.messageEditorRequestResponse().get().requestResponse())
            }
            else {
                emptyList<HttpRequestResponse>()
            }

            if(requestResponses.isNotEmpty()) {
                return menuItems
            }
        }
        return mutableListOf<Component>()
    }

    override fun provideMenuItems(event: WebSocketContextMenuEvent?): MutableList<Component> {
        return super.provideMenuItems(event)
    }

    override fun provideMenuItems(event: AuditIssueContextMenuEvent?): MutableList<Component> {
        return super.provideMenuItems(event)
    }


}


//class MyExtensionSettings {
//    val settingsPanelBuilder : SettingsPanelBuilder = SettingsPanelBuilder.settingsPanel()
//        .withPersistence(SettingsPanelPersistence.PROJECT_SETTINGS)
//        .withTitle("Auto Name Repeater")
//        .withDescription("Update Settings")
//        .withKeywords("Auto Name")
//
//    private val settingsManager = PanelSettingsDelegate(settingsPanelBuilder)
//
//    val useTitleInOrganizerNotesSetting: Boolean by settingsManager.booleanSetting("Use the webpage title as part of the organizer notes", false)
//    val tagGroupsInOrganizerNotesSetting: Boolean by settingsManager.booleanSetting("When items are submitted to organizer together, tag them", false)
//
//    val prependStringToOrganizerNotesSetting: String by settingsManager.stringSetting("Prepend this string to organizer notes", "")
//    val appendStringToOrganizerNotesSetting: String by settingsManager.stringSetting("Append this string to organizer notes", "")
//    val highlightColorForOrganizerSetting: String by settingsManager.listSetting("Color to highlight in when sending to organizer",HighlightColor.entries.map { it.name }.toMutableList(), HighlightColor.NONE.name)
//
//
//    val settingsPanel = settingsManager.buildSettingsPanel()
//
//
//}
