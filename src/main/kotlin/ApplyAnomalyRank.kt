import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse.SelectionContext
import burp.api.montoya.ui.hotkey.HotKey
import burp.api.montoya.ui.hotkey.HotKeyContext
import burp.api.montoya.ui.hotkey.HotKeyEvent
import burp.api.montoya.ui.hotkey.HotKeyHandler
import com.nickcoblentz.montoya.LogLevel
import com.nickcoblentz.montoya.MontoyaLogger
import com.nickcoblentz.montoya.registerGlobalHotKey
import java.awt.Component
import java.awt.Font
import java.awt.Robot
import java.awt.datatransfer.Clipboard
import java.awt.datatransfer.StringSelection
import java.awt.event.ActionEvent
import java.awt.event.InputEvent
import java.awt.event.KeyEvent
import java.lang.Thread.sleep
import java.util.function.Consumer
import java.util.stream.Collectors
import javax.swing.AbstractAction
import javax.swing.JLabel
import javax.swing.JMenuItem
import javax.swing.KeyStroke
import kotlin.time.Clock
import kotlin.time.ExperimentalTime


// Montoya API Documentation: https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/MontoyaApi.html
// Montoya Extension Examples: https://github.com/PortSwigger/burp-extensions-montoya-api-examples

class ApplyAnomalyRank(private val api: MontoyaApi) : ContextMenuItemsProvider {
    private val anomRankRequestResponses = mutableListOf<HttpRequestResponse>()

    private val logger: MontoyaLogger = MontoyaLogger(api, LogLevel.DEBUG)
    private val applyAnomalyRankMenuItem = JMenuItem("Apply")
    private val label = JLabel("  Anomaly Rank").apply {
        isEnabled = false
        font = font.deriveFont(Font.BOLD)
    }

    private val menuItems : MutableList<Component> = mutableListOf(label,applyAnomalyRankMenuItem)

    //private val projectSettings : MyProjectSettings by lazy { MyProjectSettings() }

    companion object {
        const val EXTENSION_NAME = "Apply Anomaly Rank"
    }

    init {
        logger.debugLog("initializing Anomaly Rank...")
        applyAnomalyRankMenuItem.addActionListener {
                e -> applyAnomalyRank()
        }

//        registerGlobalHotKey(KeyStroke.getKeyStroke(KeyEvent.VK_R,KeyEvent.CTRL_DOWN_MASK or KeyEvent.ALT_DOWN_MASK),"Apply Anomaly Rank", object : AbstractAction() {
//            override fun actionPerformed(e: ActionEvent?) {
//                logger.debugLog("Hot Key pressed!")
//                val robot = Robot()
//                robot.mousePress(InputEvent.BUTTON3_DOWN_MASK)
//                robot.mouseRelease(InputEvent.BUTTON3_DOWN_MASK)
//                //robot.delay(1000)
//                sleep(1000)
//                robot.keyPress(KeyEvent.VK_ESCAPE)
//                robot.keyRelease(KeyEvent.VK_ESCAPE)
//                applyAnomalyRankMenuItem.doClick()
//            }
//        })

//        val hotKey = HotKey.hotKey("Apply Anomaly Rank", "Ctrl+Alt+R")
//
//        val handler = HotKeyHandler { event: HotKeyEvent ->
//            event.messageEditorRequestResponse().ifPresent(Consumer { editor: MessageEditorHttpRequestResponse? ->
//                val selectionContext = editor!!.selectionContext()
//                val requestResponse = editor.requestResponse()
//
//                val headers =
//                    if (selectionContext == SelectionContext.REQUEST)
//                        requestResponse.request().headers()
//                    else
//                        requestResponse.response().headers()
//
//                val joinedHeaders = headers.stream()
//                    .map<String?> { obj: HttpHeader? -> obj!!.name() }
//                    .collect(Collectors.joining(","))
//
//                val clipboard: Clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
//                clipboard.setContents(StringSelection(joinedHeaders), null)
//            })
//        }
//
//        api.userInterface().registerHotKeyHandler(
//            HotKeyContext.HTTP_MESSAGE_EDITOR,
//            hotKey,
//            handler
//        )

        logger.debugLog("...Finished Anomaly Rank Init.")
    }

    @OptIn(ExperimentalTime::class)
    private fun applyAnomalyRank() {
        logger.debugLog("Applying Anomaly Rank...")
        Thread.ofVirtual().start {
            val rankedRequests = api.utilities().rankingUtils().rank(anomRankRequestResponses)
            val timestamp = Clock.System.now().epochSeconds
            val maxRank = rankedRequests.maxOf { it.rank() }
            val maxLength = maxRank.toString().length

            for (i in anomRankRequestResponses.indices) {


                if (i < rankedRequests.size) {
                    val floatRank = rankedRequests[i].rank()


                    anomRankRequestResponses[i].annotations()
                        .setNotes("Anom Rank $timestamp: ${String.format("%0${maxLength}d", floatRank)}")
                }

            }
        }
    }

    override fun provideMenuItems(event: ContextMenuEvent?): List<Component?> {
        logger.debugLog("Enter provideMenuItems")
        event?.let { nonNullEvent ->
            event.selectedRequestResponses().let { selectedRequestResponse ->
                logger.debugLog("Found ${selectedRequestResponse.size} requests")
                anomRankRequestResponses.clear()
                anomRankRequestResponses.addAll(selectedRequestResponse)
                return menuItems
            }
        }

        return emptyList()
    }
}


//class MyProjectSettings() {
//    val settingsPanelBuilder : SettingsPanelBuilder = SettingsPanelBuilder.settingsPanel()
//        .withPersistence(SettingsPanelPersistence.PROJECT_SETTINGS) // you can change this to user settings if you wish
//        .withTitle(YourBurpKotlinExtensionName.EXTENSION_NAME)
//        .withDescription("Add your description here")
//        .withKeywords("Add Keywords","Here")
//
//    private val settingsManager = PanelSettingsDelegate(settingsPanelBuilder)
//
//    val example1Setting: String by settingsManager.stringSetting("An example string setting here", "test default value here")
//    val example2Setting: Boolean by settingsManager.booleanSetting("An example boolean setting here", false)
//
//    val settingsPanel = settingsManager.buildSettingsPanel()
//}