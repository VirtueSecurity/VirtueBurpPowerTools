package com.nickcoblentz.montoya

import MyExtensionSettings
import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.persistence.PersistedList
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import burp.api.montoya.ui.contextmenu.AuditIssueContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider
import burp.api.montoya.ui.contextmenu.WebSocketContextMenuEvent
import java.awt.BorderLayout
import java.awt.Component
import java.awt.Dialog
import java.awt.FlowLayout
import java.awt.Font
import java.awt.GridLayout
import javax.swing.BoxLayout
import javax.swing.ButtonGroup
import javax.swing.JButton
import javax.swing.JComboBox
import javax.swing.JDialog
import javax.swing.JLabel
import javax.swing.JMenuItem
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JRadioButton
import javax.swing.JSeparator
import javax.swing.JTextField
import javax.swing.SwingUtilities
import javax.swing.border.EmptyBorder
import kotlin.jvm.optionals.getOrNull

class ManualScanIssueManager(private val api: MontoyaApi, private val myExtensionSettings : MyExtensionSettings) : ContextMenuItemsProvider {

    companion object {
        const val PLUGIN_NAME: String = "Manual Scan Issue Manager"
    }

    private var logger = MontoyaLogger(api, LogLevel.DEBUG)
    val categories = mutableSetOf(
        "Anonymous Access",
        "Role-Based Authorization Violation",
        "Tenant-Authorization Violation",
        "Contextual-Authorization Violation",
        "Cross-Site Scripting",
        "SQL Injection",
        "Other"
    )

    //val labels = mutableSetOf<String>()
    val labelSettingKey = "LABELS"
    val labelsSetting = if(api.persistence().extensionData().stringListKeys().contains(labelSettingKey)) {
        api.persistence().extensionData().getStringList(labelSettingKey)
    }
    else {
        PersistedList.persistedStringList()
    }


//    val existingIssues : MutableMap<String, MutableList<AuditIssue>> = categories.associateWith { mutableListOf<AuditIssue>() }.toMutableMap()
    val menuItem = JMenuItem("Log Manual Scan Issue")

    val label = JLabel("  Manual Issue").apply {
        isEnabled = false
        font = font.deriveFont(Font.BOLD)
    }

    private val allMenuItems = mutableListOf<Component>(
        label,
        menuItem,
        JSeparator()
    )

    var selectedRequests = mutableListOf<HttpRequestResponse>()


    init {
        logger.debugLog("Starting ${PLUGIN_NAME}...")
        api.userInterface().registerContextMenuItemsProvider(this)
        menuItem.addActionListener {
            showIssueDialog()
        }

        val labelsSetting = PersistedList.persistedStringList()


        logger.debugLog("Finished loading ${PLUGIN_NAME}...")
    }


    override fun provideMenuItems(event: ContextMenuEvent?): MutableList<Component> {
        event?.let { event ->
            selectedRequests = if(event.selectedRequestResponses()!=null && !event.selectedRequestResponses().isEmpty()) {
                logger.debugLog("Found selected request: ${event.selectedRequestResponses().count()}")
                event.selectedRequestResponses()
            }
            else if(event.messageEditorRequestResponse().getOrNull()!=null) {
                logger.debugLog("found message editor RqRs")
                mutableListOf(event.messageEditorRequestResponse().get().requestResponse())
            }
            else {
                mutableListOf()
            }

            if (selectedRequests.isNotEmpty()) {
                return allMenuItems
            }
        }

        return mutableListOf<Component>()
    }

    private fun showIssueDialog() {
        val dialog = JDialog(
            SwingUtilities.getWindowAncestor(api.userInterface().swingUtils().suiteFrame()),
            "Create Manual Scan Issue",
            Dialog.ModalityType.APPLICATION_MODAL
        )
        dialog.layout = BorderLayout()
        dialog.setSize(500, 350)
        dialog.setLocationRelativeTo(null)



        // Panel for form elements
        val formPanel = JPanel()
        formPanel.layout = BoxLayout(formPanel, BoxLayout.Y_AXIS)
        formPanel.border = EmptyBorder(10, 10, 10, 10)

        // Category Selection
        val categoryPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        categoryPanel.add(JLabel("Issue Category:"))
        val categoryCombo = JComboBox(categories.toTypedArray())
        categoryPanel.add(categoryCombo)
        formPanel.add(categoryPanel)

        // Label Selection Logic
        val radioPanel = JPanel(GridLayout(2, 1))
        val newLabelRadio = JRadioButton("New Label", true)
        val existingLabelRadio = JRadioButton("Add to Existing Label")
        val radioGroup = ButtonGroup()
        radioGroup.add(newLabelRadio)
        radioGroup.add(existingLabelRadio)

        radioPanel.add(newLabelRadio)
        radioPanel.add(existingLabelRadio)
        formPanel.add(radioPanel)

        // New Label Input
        val newLabelPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        newLabelPanel.add(JLabel("New Label Name:"))
        val newLabelField = JTextField(20)
        newLabelPanel.add(newLabelField)
        formPanel.add(newLabelPanel)

        // Existing Label Dropdown
        val existingLabelPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        existingLabelPanel.add(JLabel("Select Existing:"))
        val existingLabelCombo = JComboBox(labelsSetting.toTypedArray())
        existingLabelCombo.isEnabled = false
        existingLabelPanel.add(existingLabelCombo)
        formPanel.add(existingLabelPanel)

        // Dynamic behavior for inputs
        categoryCombo.addActionListener {
            updateExistingLabels(categoryCombo, existingLabelCombo)
        }

        newLabelRadio.addActionListener {
            newLabelField.isEnabled = true
            existingLabelCombo.isEnabled = false
        }

        existingLabelRadio.addActionListener {
            newLabelField.isEnabled = false
            existingLabelCombo.isEnabled = true
            updateExistingLabels(categoryCombo, existingLabelCombo)
        }

        // Initialize combo box state
        updateExistingLabels(categoryCombo, existingLabelCombo)

        // Buttons
        val buttonPanel = JPanel(FlowLayout(FlowLayout.RIGHT))
        val saveButton = JButton("Create / Update Issue")
        val cancelButton = JButton("Cancel")

        saveButton.addActionListener {
            val category = categoryCombo.selectedItem as String
            val label: String

            if (newLabelRadio.isSelected) {
                label = newLabelField.text.trim()
                if (label.isEmpty()) {
                    JOptionPane.showMessageDialog(dialog, "Please enter a label name.")
                    return@addActionListener
                }
                else {
                    labelsSetting.add(label)
                }
            } else {
                label = existingLabelCombo.selectedItem as? String ?: ""
                if (label.isEmpty()) {
                    JOptionPane.showMessageDialog(dialog, "Please select an existing label.")
                    return@addActionListener
                }
            }

            createOrUpdateIssue(category, label)
            dialog.dispose()
        }

        cancelButton.addActionListener { dialog.dispose() }

        buttonPanel.add(cancelButton)
        buttonPanel.add(saveButton)

        dialog.add(formPanel, BorderLayout.CENTER)
        dialog.add(buttonPanel, BorderLayout.SOUTH)
        dialog.isVisible = true
    }

    private fun createOrUpdateIssue(category: String, label: String) {

        selectedRequests.forEach { requestResponse ->
            logger.debugLog("Creating Issue for $category: $label - ${requestResponse.request().url()}")

            val auditIssue = AuditIssue.auditIssue(
                /* name = */ "$category [$label]",
                /* detail = */ "",
                /* remediation = */ "",
                /* baseUrl = */ requestResponse.request().url(),
                /* severity = */ AuditIssueSeverity.HIGH, // Default to High, logic could be expanded to select this
                /* confidence = */ AuditIssueConfidence.CERTAIN,
                /* background = */ "",
                /* remediationBackground = */ "",
                /* typicalSeverity = */ AuditIssueSeverity.HIGH,
                /* ...requestResponses = */ requestResponse
            )

            api.siteMap().add(auditIssue)

            val distinct = labelsSetting.distinct()
            labelsSetting.clear()
            labelsSetting.addAll(distinct)
            api.persistence().extensionData().setStringList(labelSettingKey,labelsSetting)
        }
    }

    private fun updateExistingLabels(categoryCombo: JComboBox<String>, existingLabelCombo: JComboBox<String>) {

        existingLabelCombo.removeAllItems()
        if (labelsSetting.isNotEmpty()) {
            for (label in labelsSetting) {
                existingLabelCombo.addItem(label)
            }
        }
    }

    override fun provideMenuItems(event: WebSocketContextMenuEvent?): MutableList<Component> {
        return mutableListOf<Component>()
    }

    override fun provideMenuItems(event: AuditIssueContextMenuEvent?): MutableList<Component> {
        return mutableListOf<Component>()
    }
}

