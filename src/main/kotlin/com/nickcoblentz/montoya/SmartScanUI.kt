import burp.api.montoya.MontoyaApi
import com.nickcoblentz.montoya.SmartScanViewModel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import java.awt.*
import java.awt.datatransfer.StringSelection
import javax.swing.*
import javax.swing.border.CompoundBorder
import javax.swing.border.EmptyBorder
import javax.swing.border.LineBorder
import javax.swing.border.TitledBorder
import kotlin.math.max
import kotlin.math.min

class SmartScanUI(private val api: MontoyaApi, private val viewModel: SmartScanViewModel) {
    private val rootPanel: JTabbedPane = JTabbedPane()
    private val uiScope = CoroutineScope(Dispatchers.Main)

    // Define some constants for modern look
    private val PADDING = 15
    private val COMPONENT_SPACING = 10
    private val SECTION_SPACING = 25
    private val BORDER_COLOR = Color(200, 200, 200)
    private val SECONDARY_TEXT_COLOR = Color(100, 100, 100)
    private val METRIC_VALUE_COLOR = Color(0, 102, 204) // Professional blue to make values stand out

    // Font scaling
    private val BASE_FONT_SIZE = 16f
    private val HEADER_FONT_SIZE = 28f
    private val SUBHEADER_FONT_SIZE = 20f
    private val METRIC_LABEL_FONT_SIZE = 18f
    private val METRIC_VALUE_FONT_SIZE = 18f
    private val SMALL_FONT_SIZE = 14f

    init {
        rootPanel.addTab("Scan Setup", createScanSetupTab())
        rootPanel.addTab("Monitor Scan", createMonitorScanTab())
        rootPanel.addTab("Logs", createLogsTab())
    }

    private fun createLogsTab(): JComponent {
        val panel = JPanel(BorderLayout())
        panel.border = EmptyBorder(PADDING, PADDING, PADDING, PADDING)
        panel.background = Color.WHITE

        val tabbedPane = JTabbedPane()
        
        val actionsTextArea = JTextArea().apply {
            isEditable = false
            font = Font(Font.MONOSPACED, Font.PLAIN, SMALL_FONT_SIZE.toInt())
        }
        val actionsScrollPane = JScrollPane(actionsTextArea)
        tabbedPane.addTab("Actions", actionsScrollPane)

        val errorsTextArea = JTextArea().apply {
            isEditable = false
            font = Font(Font.MONOSPACED, Font.PLAIN, SMALL_FONT_SIZE.toInt())
            foreground = Color.RED
        }
        val errorsScrollPane = JScrollPane(errorsTextArea)
        tabbedPane.addTab("Errors", errorsScrollPane)

        uiScope.launch {
            viewModel.actions.collectLatest { actions ->
                val text = actions.joinToString("\n") { 
                    "[${it.timestamp}] ${it.message}"
                }
                actionsTextArea.text = text
            }
        }

        uiScope.launch {
            viewModel.errors.collectLatest { errors ->
                val text = errors.joinToString("\n") { 
                    "[${it.timestamp}] ${it.message}"
                }
                errorsTextArea.text = text
            }
        }

        panel.add(tabbedPane, BorderLayout.CENTER)
        return panel
    }

    fun getRootComponent(): Component {
        return rootPanel
    }

    private fun createScanSetupTab(): JComponent {
        val panel = JPanel()
        panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
        panel.border = EmptyBorder(PADDING, PADDING, PADDING, PADDING)
        panel.background = Color.WHITE

        // Increase default font for the panel
        panel.font = panel.font.deriveFont(BASE_FONT_SIZE)

        // Unified Scan Setup Section
        val setupPanel = createSectionPanel("Step 1: Scan Setup")

        val instructions = JLabel("<html><b>Instructions:</b> Sort the organizer results by <i>Notes</i> then delete/remove any items you do not wish to keep.</html>")
        instructions.putClientProperty("html.disable", null)
        instructions.font = instructions.font.deriveFont(BASE_FONT_SIZE)
        instructions.foreground = SECONDARY_TEXT_COLOR
        instructions.border = EmptyBorder(0, 0, COMPONENT_SPACING, 0)
        instructions.alignmentX = Component.LEFT_ALIGNMENT
        setupPanel.add(instructions)

        // Unified Subsection: Results Quality & Scan Control
        val unifiedPanel = createSubsectionPanel("Metrics & Scan Control")
        
        val qualityInfo = JLabel("Information: Metrics based on currently check-marked grades below")
        qualityInfo.font = qualityInfo.font.deriveFont(Font.ITALIC, BASE_FONT_SIZE)
        unifiedPanel.add(qualityInfo)
        unifiedPanel.add(Box.createRigidArea(Dimension(0, COMPONENT_SPACING)))

        val metricsPanel = JPanel(GridLayout(0, 2, 20, 10))
        metricsPanel.isOpaque = false
        
        val gradesLabel = (createMetricLabel("Grades:", "").components[1] as JLabel).apply {
            putClientProperty("html.disable", null)
        }
        val statusLabel = (createMetricLabel("HTTP Status Codes:", "").components[1] as JLabel).apply {
            putClientProperty("html.disable", null)
        }
        val responseTimesLabel = (createMetricLabel("Response Times:", "").components[1] as JLabel).apply {
            putClientProperty("html.disable", null)
        }

        metricsPanel.add(gradesLabel.parent)
        metricsPanel.add(statusLabel.parent)
        metricsPanel.add(responseTimesLabel.parent)
        
        uiScope.launch {
            viewModel.metrics.collectLatest { metrics ->
                gradesLabel.text = "<html><b>A:</b> <font color='#0066CC'>${metrics.gradeA}</font> / <font color='#666666'>${metrics.gradeATotal}</font><br/>" +
                                   "<b>B:</b> <font color='#0066CC'>${metrics.gradeB}</font> / <font color='#666666'>${metrics.gradeBTotal}</font><br/>" +
                                   "<b>C:</b> <font color='#0066CC'>${metrics.gradeC}</font> / <font color='#666666'>${metrics.gradeCTotal}</font><br/>" +
                                   "<b>D:</b> <font color='#0066CC'>${metrics.gradeD}</font> / <font color='#666666'>${metrics.gradeDTotal}</font><br/>" +
                                   "<b>F:</b> <font color='#0066CC'>${metrics.gradeF}</font> / <font color='#666666'>${metrics.gradeFTotal}</font><br/>" +
                                   "<b>Total:</b> <font color='#0066CC'>${metrics.totalGrades}</font> / <font color='#666666'>${metrics.totalGradesTotal}</font></html>"
                
                statusLabel.text = "<html><b>200s:</b> <font color='#0066CC'>${metrics.status200s}</font> / <font color='#666666'>${metrics.status200sTotal}</font><br/>" +
                                   "<b>300s:</b> <font color='#0066CC'>${metrics.status300s}</font> / <font color='#666666'>${metrics.status300sTotal}</font><br/>" +
                                   "<b>400s:</b> <font color='#0066CC'>${metrics.status400s}</font> / <font color='#666666'>${metrics.status400sTotal}</font><br/>" +
                                   "<b>500s:</b> <font color='#0066CC'>${metrics.status500s}</font> / <font color='#666666'>${metrics.status500sTotal}</font><br/>" +
                                   "<b>Fail:</b> <font color='#0066CC'>${metrics.statusFail}</font> / <font color='#666666'>${metrics.statusFailTotal}</font></html>"
                
                responseTimesLabel.text = "<html><b>Min:</b> <font color='#0066CC'>${metrics.minResponseTime}</font><br/>" +
                                          "<b>Max:</b> <font color='#0066CC'>${metrics.maxResponseTime}</font><br/>" +
                                          "<b>Avg:</b> <font color='#0066CC'>${metrics.avgResponseTime}</font></html>"
            }
        }
        
        metricsPanel.alignmentX = Component.LEFT_ALIGNMENT
        unifiedPanel.add(metricsPanel)
        unifiedPanel.add(Box.createRigidArea(Dimension(0, SECTION_SPACING)))

        val gradeLabel = JLabel("Select Grades to Include:")
        gradeLabel.font = gradeLabel.font.deriveFont(Font.BOLD, BASE_FONT_SIZE)
        unifiedPanel.add(gradeLabel)

        val gradeCheckboxes = JPanel(FlowLayout(FlowLayout.LEFT, 0, 5))
        gradeCheckboxes.isOpaque = false
        val cbA = createModernCheckBox("Grade: A", true).apply { addActionListener { viewModel.updateCheckbox("A", isSelected) } }
        val cbB = createModernCheckBox("Grade: B", true).apply { addActionListener { viewModel.updateCheckbox("B", isSelected) } }
        val cbC = createModernCheckBox("Grade: C", true).apply { addActionListener { viewModel.updateCheckbox("C", isSelected) } }
        val cbD = createModernCheckBox("Grade: D", false).apply { addActionListener { viewModel.updateCheckbox("D", isSelected) } }
        val cbF = createModernCheckBox("Grade: F", false).apply { addActionListener { viewModel.updateCheckbox("F", isSelected) } }

        gradeCheckboxes.add(cbA)
        gradeCheckboxes.add(cbB)
        gradeCheckboxes.add(cbC)
        gradeCheckboxes.add(cbD)
        gradeCheckboxes.add(cbF)
        gradeCheckboxes.alignmentX = Component.LEFT_ALIGNMENT
        unifiedPanel.add(gradeCheckboxes)

        uiScope.launch {
            viewModel.checkboxes.collectLatest { state ->
                cbA.isSelected = state.gradeA
                cbB.isSelected = state.gradeB
                cbC.isSelected = state.gradeC
                cbD.isSelected = state.gradeD
                cbF.isSelected = state.gradeF
            }
        }

        val buttonPanel = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0))
        buttonPanel.isOpaque = false
        buttonPanel.alignmentX = Component.LEFT_ALIGNMENT

        val copyCrawlFilterBtn = createModernButton("Copy Crawl Filter", "Copies the crawl filter code to the clipboard.").apply {
            addActionListener {
                val textToCopy = "return requestResponse.request().hasParameter(\"x-virtue-task\", HttpParameterType.COOKIE) && requestResponse.request().parameterValue(\"x-virtue-task\", HttpParameterType.COOKIE).toLowerCase().contains(\"crawl\");"
                val selection = StringSelection(textToCopy)
                Toolkit.getDefaultToolkit().systemClipboard.setContents(selection, selection)
            }
        }

        val gradeOrganizerBtn = createModernButton("Grade organizer items", "Automatically assigns initial grades to items in the organizer based on predefined criteria.").apply {
            addActionListener { viewModel.gradeOrganizerItems() }
        }
        
        val beginScanBtn = createModernButton("Begin Scan", "Starts the automated scanning process for the selected items.").apply {
            addActionListener { viewModel.beginScan() }
        }
        beginScanBtn.font = beginScanBtn.font.deriveFont(Font.BOLD, 18f)
        beginScanBtn.margin = Insets(12, 24, 12, 24)

        buttonPanel.add(copyCrawlFilterBtn)
        buttonPanel.add(Box.createRigidArea(Dimension(COMPONENT_SPACING, 0)))
        buttonPanel.add(gradeOrganizerBtn)
        buttonPanel.add(Box.createRigidArea(Dimension(COMPONENT_SPACING, 0)))
        buttonPanel.add(beginScanBtn)

        unifiedPanel.add(Box.createRigidArea(Dimension(0, COMPONENT_SPACING)))
        unifiedPanel.add(buttonPanel)

        setupPanel.add(unifiedPanel)
        panel.add(setupPanel)
        
        panel.add(Box.createVerticalGlue())

        return JScrollPane(panel).apply {
            border = null
        }
    }

    private fun createMonitorScanTab(): JComponent {
        val panel = JPanel()
        panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
        panel.border = EmptyBorder(PADDING, PADDING, PADDING, PADDING)
        panel.background = Color.WHITE

        val monitorPanel = createSectionPanel("Step 3: Monitor Scan")

        val chartGrid = JPanel(GridLayout(0, 1, COMPONENT_SPACING, COMPONENT_SPACING))
        chartGrid.isOpaque = false
        chartGrid.alignmentX = Component.LEFT_ALIGNMENT

        val rpsChart = LineChart("Requests Per Second", listOf(
            ChartSeries("Total", Color.BLACK),
            ChartSeries("200s", Color(40, 167, 69)), // Green
            ChartSeries("400s", Color(255, 193, 7)), // Amber
            ChartSeries("5xx", Color(220, 53, 69)),  // Red
            ChartSeries("Redirects", Color(0, 123, 255)), // Blue
            ChartSeries("Timeout/NoResp", Color.GRAY)
        ))

        val timingChart = LineChart("Response Times (ms)", listOf(
            ChartSeries("Avg Response Time", Color.BLUE)
        ))

        uiScope.launch {
            viewModel.scannerMonitorState.collectLatest { state ->
                rpsChart.updateData(listOf(
                    state.totalRps,
                    state.status200Rps,
                    state.status400Rps,
                    state.status5xxRps,
                    state.redirectRps,
                    state.timeoutRps
                ))
                
                timingChart.updateData(listOf(state.avgResponseTime))
                timingChart.setSubtitle("Highest in last: 1m:${state.maxResponseTime1m.toInt()}ms, 5m:${state.maxResponseTime5m.toInt()}ms, 15m:${state.maxResponseTime15m.toInt()}ms, 30m:${state.maxResponseTime30m.toInt()}ms, 60m:${state.maxResponseTime60m.toInt()}ms")
            }
        }

        chartGrid.add(rpsChart)
        chartGrid.add(timingChart)

        monitorPanel.add(chartGrid)
        panel.add(monitorPanel)
        panel.add(Box.createVerticalGlue())

        return JScrollPane(panel).apply {
            border = null
        }
    }

    private class ChartSeries(val name: String, val color: Color)

    private inner class LineChart(val title: String, val series: List<ChartSeries>) : JPanel(BorderLayout()) {
        private var data: List<List<Double>> = emptyList()
        private var subtitleText: String = ""
        private val subtitleLabel = JLabel()
        private val chartPadding = 40
        private val headerHeight = 80

        init {
            background = Color.WHITE
            border = CompoundBorder(
                LineBorder(BORDER_COLOR, 1, true),
                EmptyBorder(10, 10, 10, 10)
            )
            preferredSize = Dimension(400, 300)

            val header = JPanel(BorderLayout())
            header.isOpaque = false
            
            val titleContainer = JPanel(GridLayout(2, 1))
            titleContainer.isOpaque = false
            
            val t = JLabel(title)
            t.font = t.font.deriveFont(Font.BOLD, METRIC_VALUE_FONT_SIZE)
            titleContainer.add(t)
            
            subtitleLabel.font = subtitleLabel.font.deriveFont(SMALL_FONT_SIZE)
            subtitleLabel.foreground = SECONDARY_TEXT_COLOR
            titleContainer.add(subtitleLabel)
            
            header.add(titleContainer, BorderLayout.NORTH)

            // Legend
            val legend = JPanel(FlowLayout(FlowLayout.LEFT, 5, 0))
            legend.isOpaque = false
            series.forEach { s ->
                val colorBox = object : JPanel() {
                    override fun paintComponent(g: Graphics) {
                        g.color = s.color
                        g.fillRect(0, 4, 12, 12)
                    }
                }
                colorBox.preferredSize = Dimension(15, 20)
                colorBox.isOpaque = false
                
                val l = JLabel(s.name)
                l.font = l.font.deriveFont(SMALL_FONT_SIZE)
                
                legend.add(colorBox)
                legend.add(l)
            }
            header.add(legend, BorderLayout.CENTER)

            add(header, BorderLayout.NORTH)
        }

        fun updateData(newData: List<List<Double>>) {
            this.data = newData
            repaint()
        }

        fun setSubtitle(text: String) {
            this.subtitleText = text
            subtitleLabel.text = text
        }

        override fun paintComponent(g: Graphics) {
            super.paintComponent(g)
            val g2 = g as Graphics2D
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)

            val w = width - 2 * chartPadding
            val h = height - headerHeight - chartPadding

            // Find global max for scaling
            val maxVal = data.flatten().maxOrNull() ?: 1.0
            val scale = if (maxVal > 0) h / maxVal else 1.0

            val chartYBase = height - chartPadding

            // Draw axes
            g2.color = Color.LIGHT_GRAY
            g2.stroke = BasicStroke(1f)
            g2.drawLine(chartPadding, chartYBase, chartPadding + w, chartYBase) // X axis
            g2.drawLine(chartPadding, chartYBase, chartPadding, chartYBase - h) // Y axis

            // Draw Y axis labels (min/max)
            g2.color = SECONDARY_TEXT_COLOR
            g2.font = g2.font.deriveFont(SMALL_FONT_SIZE)
            g2.drawString("0", chartPadding - 20, chartYBase + 5)
            g2.drawString(maxVal.toInt().toString(), chartPadding - 25, chartYBase - h + 5)

            if (data.isEmpty() || data[0].isEmpty()) return

            data.forEachIndexed { sIdx, points ->
                if (sIdx >= series.size) return@forEachIndexed
                g2.color = series[sIdx].color
                
                // Use different stroke styles for different series if they overlap
                // Total (sIdx 0) is thickest, others are standard
                if (sIdx == 0) {
                    g2.stroke = BasicStroke(2f)
                } else {
                    g2.stroke = BasicStroke(2f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND, 0f, if (sIdx % 2 == 0) floatArrayOf(5f, 5f) else null, 0f)
                }
                
                val xStep = w.toDouble() / (points.size - 1).coerceAtLeast(1)
                
                for (i in 0 until points.size - 1) {
                    val x1 = chartPadding + (i * xStep).toInt()
                    val y1 = chartYBase - (points[i] * scale).toInt()
                    val x2 = chartPadding + ((i + 1) * xStep).toInt()
                    val y2 = chartYBase - (points[i + 1] * scale).toInt()
                    g2.drawLine(x1, y1, x2, y2)
                }
            }
        }
    }

    private fun createSectionPanel(title: String): JPanel {
        val panel = JPanel()
        panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
        panel.isOpaque = false
        panel.alignmentX = Component.LEFT_ALIGNMENT
        
        val titleLabel = JLabel(title)
        titleLabel.font = titleLabel.font.deriveFont(Font.BOLD, HEADER_FONT_SIZE)
        titleLabel.border = EmptyBorder(0, 0, 10, 0)
        panel.add(titleLabel)
        
        return panel
    }

    private fun createSubsectionPanel(title: String): JPanel {
        val panel = JPanel()
        panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
        panel.background = Color(245, 245, 245)
        panel.border = CompoundBorder(
            LineBorder(BORDER_COLOR, 1, true),
            EmptyBorder(PADDING, PADDING, PADDING, PADDING)
        )
        panel.alignmentX = Component.LEFT_ALIGNMENT

        val subTitle = JLabel(title.uppercase())
        subTitle.font = subTitle.font.deriveFont(Font.BOLD, SUBHEADER_FONT_SIZE)
        subTitle.foreground = SECONDARY_TEXT_COLOR
        subTitle.border = EmptyBorder(0, 0, 10, 0)
        panel.add(subTitle)

        return panel
    }

    private fun createMetricLabel(label: String, value: String): JPanel {
        val p = JPanel()
        p.layout = BoxLayout(p, BoxLayout.Y_AXIS)
        p.isOpaque = false
        p.alignmentX = Component.LEFT_ALIGNMENT

        val l = JLabel(label)
        l.font = l.font.deriveFont(Font.BOLD, METRIC_LABEL_FONT_SIZE)
        
        val v = JLabel(value)
        v.font = v.font.deriveFont(Font.PLAIN, METRIC_VALUE_FONT_SIZE)
        v.border = EmptyBorder(2, 0, 8, 0)
        
        p.add(l)
        p.add(v)
        return p
    }

    private fun createModernButton(text: String, tooltip: String): JButton {
        val btn = JButton(text)
        btn.toolTipText = tooltip
        btn.isFocusPainted = false
        btn.font = btn.font.deriveFont(BASE_FONT_SIZE)
        return btn
    }

    private fun createModernCheckBox(text: String, selected: Boolean): JCheckBox {
        val cb = JCheckBox(text, selected)
        cb.isOpaque = false
        cb.margin = Insets(0, 0, 0, 10)
        cb.font = cb.font.deriveFont(BASE_FONT_SIZE)
        return cb
    }

    private fun createChartPlaceholder(title: String, subtitle: String): JPanel {
        val p = JPanel(BorderLayout())
        p.background = Color.WHITE
        p.border = CompoundBorder(
            LineBorder(BORDER_COLOR, 1, true),
            EmptyBorder(10, 10, 10, 10)
        )
        p.preferredSize = Dimension(400, 150)

        val header = JPanel(GridLayout(2, 1))
        header.isOpaque = false
        val t = JLabel(title)
        t.font = t.font.deriveFont(Font.BOLD, METRIC_VALUE_FONT_SIZE)
        val st = JLabel(subtitle)
        st.font = st.font.deriveFont(SMALL_FONT_SIZE)
        st.foreground = SECONDARY_TEXT_COLOR
        header.add(t)
        header.add(st)
        p.add(header, BorderLayout.NORTH)

        val body = JLabel("Visual Chart Data Placeholder", SwingConstants.CENTER)
        body.font = body.font.deriveFont(BASE_FONT_SIZE)
        body.foreground = Color(180, 180, 180)
        p.add(body, BorderLayout.CENTER)

        return p
    }
}
