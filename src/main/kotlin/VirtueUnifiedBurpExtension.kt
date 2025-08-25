import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.HighlightColor
import burp.api.montoya.ui.settings.SettingsPanelBuilder
import burp.api.montoya.ui.settings.SettingsPanelPersistence
import com.nickcoblentz.montoya.EveryParameter
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


        api.userInterface().registerSettingsPanel(projectSettings.settingsPanel)


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


    val settingsPanel = settingsManager.buildSettingsPanel()


}