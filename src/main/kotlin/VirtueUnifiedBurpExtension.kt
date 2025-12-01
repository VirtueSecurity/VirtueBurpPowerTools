import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.HighlightColor
import burp.api.montoya.ui.settings.SettingsPanelBuilder
import burp.api.montoya.ui.settings.SettingsPanelPersistence
import com.nickcoblentz.montoya.DisposableEmailScanChecker
import com.nickcoblentz.montoya.EveryParameter
import com.nickcoblentz.montoya.ManualScanIssueManager
import com.nickcoblentz.montoya.settings.PanelSettingsDelegate
import com.nickcoblentz.montoya.utilities.RetryRequestsMontoya
import com.nickcoblentz.montoya.utils.CopyRequestResponse


// Montoya API Documentation: https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/MontoyaApi.html
// Montoya Extension Examples: https://github.com/PortSwigger/burp-extensions-montoya-api-examples

class VirtueUnifiedBurpExtension : BurpExtension {
    private lateinit var api: MontoyaApi


    companion object {
        const val EXTENSION_NAME = "Virtue Security Unified Burp Extension"
    }




    override fun initialize(api: MontoyaApi?) {


        this.api = requireNotNull(api) { "api : MontoyaApi is not allowed to be null" }

        api.logging().logToOutput("Started loading the extension...")



        api.extension().setName(EXTENSION_NAME)

        val projectSettings = MyExtensionSettings()

        MatchReplaceSessionExtension(api, projectSettings)
        EveryParameter(api, projectSettings)
        KotlinBurpAutoNameRepeaterTabExtension(api, projectSettings)
        RetryRequestsMontoya(api, projectSettings)
        CopyRequestResponse(api)
        MontoyaKotlinSessionAccessTokenHelper(api, projectSettings)
        DisposableEmailScanChecker(api)
        ManualScanIssueManager(api)
//        VariableExtractInjectExtension(api, projectSettings)


        api.userInterface().registerSettingsPanel(projectSettings.settingsPanel)

        api.userInterface().registerContextMenuItemsProvider(ApplyAnomalyRank(api))

        api.logging().logToOutput("...Finished loading the extension")

    }
}


class MyExtensionSettings {
    val settingsPanelBuilder : SettingsPanelBuilder = SettingsPanelBuilder.settingsPanel()
        .withPersistence(SettingsPanelPersistence.PROJECT_SETTINGS)
        .withTitle("Virtue Unified Burp Extension")
        .withDescription("")
        .withKeywords("")

    private val settingsManager = PanelSettingsDelegate(settingsPanelBuilder)

    val limitConcurrentRequestsSetting: Boolean by settingsManager.booleanSetting("RetryRequests: Limit the number of concurrent HTTP requests?", false)
    val requestLimit: Int by settingsManager.integerSetting("RetryRequests: Concurrent HTTP Request Limit", 10)





    val useTitleInOrganizerNotesSetting: Boolean by settingsManager.booleanSetting("AutoNameRepeater: Use the webpage title as part of the organizer notes", false)
    val tagGroupsInOrganizerNotesSetting: Boolean by settingsManager.booleanSetting("AutoNameRepeater: When items are submitted to organizer together, tag them", false)

    val prependStringToOrganizerNotesSetting: String by settingsManager.stringSetting("AutoNameRepeater: Prepend this string to organizer notes", "")
    val appendStringToOrganizerNotesSetting: String by settingsManager.stringSetting("AutoNameRepeater: Append this string to organizer notes", "")
    val highlightColorForOrganizerSetting: String by settingsManager.listSetting("AutoNameRepeater: Color to highlight in when sending to organizer",HighlightColor.entries.map { it.name }.toMutableList(), HighlightColor.NONE.name)




    val matchOneSetting: String by settingsManager.stringSetting("Session Match/Replace: First Match Expression", "")
    val replaceOneSetting: String by settingsManager.stringSetting("Session Match/Replace: First Replace Expression", "")

    val matchTwoSetting: String by settingsManager.stringSetting("Session Match/Replace: Second Match Expression", "")
    val replaceTwoSetting: String by settingsManager.stringSetting("Session Match/Replace: Second Replace Expression", "")

    val matchThreeSetting: String by settingsManager.stringSetting("Session Match/Replace: Third Match Expression", "")
    val replaceThreeSetting: String by settingsManager.stringSetting("Session Match/Replace: Third Replace Expression", "")



    val ignoreParametersSetting: String by settingsManager.stringSetting("Every Param: Ignore the following Parameters (RegEx)", "")
    val followRedirectSetting: Boolean by settingsManager.booleanSetting("Every Param: Follow Redirects?", false)
//    val rankAndSendToOrganizer: Boolean by settingsManager.booleanSetting("Every Param: Rank and send to Organizer?", true)


//    val varExtInjVar1SearchEnabled: Boolean by settingsManager.booleanSetting("VarExtInj: Populate {{variable1}} Search Enabled", false)
//    val varExtInjVar1Search: String by settingsManager.stringSetting("VarExtInj: Populate {{variable1}} Search Regex With Capture", "\"token\": \"([^\"]+)\"")
//
//    val varExtInjVar2SearchEnabled: Boolean by settingsManager.booleanSetting("VarExtInj: Populate {{variable2}} Search Enabled", false)
//    val varExtInjVar2Search: String by settingsManager.stringSetting("VarExtInj: Populate {{variable2}} Search Regex With Capture", "\"token\": \"([^\"]+)\"")
//
//    val varExtInjVar3SearchEnabled: Boolean by settingsManager.booleanSetting("VarExtInj: Populate {{variable3}} Search Enabled", false)
//    val varExtInjVar3Search: String by settingsManager.stringSetting("VarExtInj: Populate {{variable3}} Search Regex With Capture", "\"token\": \"([^\"]+)\"")
//
//    val varExtInjVar4SearchEnabled: Boolean by settingsManager.booleanSetting("VarExtInj: Populate {{variable4}} Search Enabled", false)
//    val varExtInjVar4Search: String by settingsManager.stringSetting("VarExtInj: Populate {{variable4}} Search Regex With Capture", "\"token\": \"([^\"]+)\"")
//
//
//    val varExtInjReplaceEnabled1: Boolean by settingsManager.booleanSetting("VarExtInj: Search/Replace 1 Enabled", false)
//    val varExtInjSearch1: String by settingsManager.stringSetting("VarExtInj: Search 1 Statement", "^token: (.+) .*$")
//    val varExtInjReplace1: String by settingsManager.stringSetting("VarExtInj: Replace 1 Statement", "token: $1 {{variable1}}")
//
//    val varExtInjReplaceEnabled2: Boolean by settingsManager.booleanSetting("VarExtInj: Search/Replace 2 Enabled", false)
//    val varExtInjSearch2: String by settingsManager.stringSetting("VarExtInj: Search 2 Statement", "^token: (.+) .*$")
//    val varExtInjReplace2: String by settingsManager.stringSetting("VarExtInj: Replace 2 Statement", "token: $1 {{variable2}}")
//
//    val varExtInjReplaceEnabled3: Boolean by settingsManager.booleanSetting("VarExtInj: Search/Replace 3 Enabled", false)
//    val varExtInjSearch3: String by settingsManager.stringSetting("VarExtInj: Search 3 Statement", "^token: (.+) .*$")
//    val varExtInjReplace3: String by settingsManager.stringSetting("VarExtInj: Replace 3 Statement", "token: $1 {{variable3}}")
//
//    val varExtInjReplaceEnabled4: Boolean by settingsManager.booleanSetting("VarExtInj: Search/Replace 4 Enabled", false)
//    val varExtInjSearch4: String by settingsManager.stringSetting("VarExtInj: Search 4 Statement", "^token: (.+) .*$")
//    val varExtInjReplace4: String by settingsManager.stringSetting("VarExtInj: Replace 4 Statement", "token: $1 {{variable4}}")


    val accessTokenPatternSetting: String by settingsManager.stringSetting("SessionAccessToken: Access Token RegEx Pattern", "\"access_token\" *: *\"([^\"]+)\"")
    val headerName1Setting: String by settingsManager.stringSetting("SessionAccessToken: Header Name 1", "Authorization")
    val headerValuePrefix1Setting: String by settingsManager.stringSetting("SessionAccessToken: Header Value Prefix 1", "Bearer ")
    val headerValueSuffix1Setting: String by settingsManager.stringSetting("SessionAccessToken: Header Value Suffix 1", "")
    val headerName2Setting: String by settingsManager.stringSetting("SessionAccessToken: Header Name 2", "")
    val headerValuePrefix2Setting: String by settingsManager.stringSetting("SessionAccessToken: Header Value Prefix 2", "")
    val headerValueSuffix2Setting: String by settingsManager.stringSetting("SessionAccessToken: Header Value Suffix 2", "")
    val ignoreEndpointsSetting: String by settingsManager.stringSetting("SessionAccessToken: Regex of URLs to Ignore when applying the token", "")

    val passiveSetting: Boolean by settingsManager.booleanSetting("SessionAccessToken: Use Passively For All Requests?", false)
    val shouldIgnoreEndpointsSetting: Boolean by settingsManager.booleanSetting("SessionAccessToken: Should Ignore Endpoints?", false)

    val settingsPanel = settingsManager.buildSettingsPanel()


}