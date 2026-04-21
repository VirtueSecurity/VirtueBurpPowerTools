package com.nickcoblentz.montoya

import burp.api.montoya.MontoyaApi
import MyExtensionSettings
import burp.api.montoya.core.Annotations
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.params.HttpParameterType
import burp.api.montoya.organizer.OrganizerItem
import burp.api.montoya.proxy.ProxyHistoryFilter
import burp.api.montoya.scanner.*
import burp.api.montoya.scanner.audit.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.json.*
import java.nio.file.Path
import kotlin.io.path.exists
import kotlin.io.path.readText
import java.time.Instant
import java.util.concurrent.ConcurrentLinkedQueue
import java.time.Duration as JavaDuration
import java.util.UUID

enum class ScannerMetricType {
    SENT,
    RECEIVED
}

data class ScannerMetric(
    val messageId: Int,
    val type: ScannerMetricType,
    val statusCode: Int,
    val timestamp: Instant
)

data class TimeSeriesData(
    val timestamps: List<Instant>,
    val totalRps: List<Double>,
    val status200Rps: List<Double>,
    val status400Rps: List<Double>,
    val status5xxRps: List<Double>,
    val redirectRps: List<Double>,
    val timeoutRps: List<Double>
)

data class MetricsState(
    val gradeA: String = "[N/A]",
    val gradeATotal: String = "[N/A]",
    val gradeB: String = "[N/A]",
    val gradeBTotal: String = "[N/A]",
    val gradeC: String = "[N/A]",
    val gradeCTotal: String = "[N/A]",
    val gradeD: String = "[N/A]",
    val gradeDTotal: String = "[N/A]",
    val gradeF: String = "[N/A]",
    val gradeFTotal: String = "[N/A]",
    val totalGrades: String = "[N/A]",
    val totalGradesTotal: String = "[N/A]",
    val status200s: String = "[N/A]",
    val status200sTotal: String = "[N/A]",
    val status300s: String = "[N/A]",
    val status300sTotal: String = "[N/A]",
    val status400s: String = "[N/A]",
    val status400sTotal: String = "[N/A]",
    val status500s: String = "[N/A]",
    val status500sTotal: String = "[N/A]",
    val statusFail: String = "[N/A]",
    val statusFailTotal: String = "[N/A]"
)

data class CheckboxState(
    val gradeA: Boolean = true,
    val gradeB: Boolean = true,
    val gradeC: Boolean = true,
    val gradeD: Boolean = false,
    val gradeF: Boolean = false
)

data class LogEntry(
    val timestamp: Instant,
    val message: String,
    val type: LogType
)

enum class LogType {
    ACTION,
    ERROR
}

class SmartScanViewModel(
    private val api: MontoyaApi,
    private val myExtensionSettings: MyExtensionSettings
) {
    private val viewModelScope = CoroutineScope(Dispatchers.Default + SupervisorJob())

    private val _actions = MutableStateFlow<List<LogEntry>>(emptyList())
    val actions: StateFlow<List<LogEntry>> = _actions.asStateFlow()

    private val _errors = MutableStateFlow<List<LogEntry>>(emptyList())
    val errors: StateFlow<List<LogEntry>> = _errors.asStateFlow()

    fun logAction(message: String) {
        val entry = LogEntry(Instant.now(), message, LogType.ACTION)
        _actions.value = (listOf(entry) + _actions.value).take(500)
    }

    fun logError(message: String) {
        val entry = LogEntry(Instant.now(), message, LogType.ERROR)
        _errors.value = (listOf(entry) + _errors.value).take(500)
    }

    private val _metrics = MutableStateFlow(MetricsState())
    val metrics: StateFlow<MetricsState> = _metrics.asStateFlow()

    private val _checkboxes = MutableStateFlow(CheckboxState())
    val checkboxes: StateFlow<CheckboxState> = _checkboxes.asStateFlow()

    private data class GradedItemResult(
        val grade: String,
        val statusBucket: Int,
        val item: OrganizerItem
    )

    private var lastGradedResults: List<GradedItemResult> = emptyList()

    private val _scannerMonitorState = MutableStateFlow(TimeSeriesData(emptyList(), emptyList(), emptyList(), emptyList(), emptyList(), emptyList(), emptyList()))
    val scannerMonitorState: StateFlow<TimeSeriesData> = _scannerMonitorState.asStateFlow()

    private val scannerMetrics = ConcurrentLinkedQueue<ScannerMetric>()

    init {
        startMetricAggregation()
    }

    fun addScannerMetric(messageId: Int, type: ScannerMetricType, statusCode: Int, timestamp: Instant) {
        scannerMetrics.add(ScannerMetric(messageId, type, statusCode, timestamp))
    }

    private fun startMetricAggregation() {
        viewModelScope.launch {
            while (isActive) {
                delay(1000) // Update every second
                updateScannerTimeSeries()
            }
        }
    }

    private fun updateScannerTimeSeries() {
        val now = Instant.now()
        val oneHourAgo = now.minusSeconds(3600)
        
        // Remove metrics older than 1 hour
        while (scannerMetrics.peek()?.timestamp?.isBefore(oneHourAgo) == true) {
            scannerMetrics.poll()
        }

        val allMetrics = scannerMetrics.toList()
        if (allMetrics.isEmpty()) {
            _scannerMonitorState.value = TimeSeriesData(emptyList(), emptyList(), emptyList(), emptyList(), emptyList(), emptyList(), emptyList())
            return
        }

        val windowSeconds = 60
        val avgWindow = 15L
        val startTime = now.minusSeconds(windowSeconds.toLong())
        val earliestNeeded = startTime.minusSeconds(avgWindow)
        
        // Filter once for the entire calculation
        val relevantMetrics = allMetrics.filter { it.timestamp >= earliestNeeded }
        if (relevantMetrics.isEmpty()) {
            _scannerMonitorState.value = TimeSeriesData(emptyList(), emptyList(), emptyList(), emptyList(), emptyList(), emptyList(), emptyList())
            return
        }

        val timestamps = mutableListOf<Instant>()
        val totalRps = mutableListOf<Double>()
        val s200Rps = mutableListOf<Double>()
        val s400Rps = mutableListOf<Double>()
        val s5xxRps = mutableListOf<Double>()
        val redirectRps = mutableListOf<Double>()
        val timeoutRps = mutableListOf<Double>()

        // Pre-process for timeouts: find SENT without RECEIVED
        val receivedIds = relevantMetrics.asSequence().filter { it.type == ScannerMetricType.RECEIVED }.map { it.messageId }.toSet()
        val timeoutThreshold = 30L // seconds

        for (i in 0..windowSeconds) {
            val secondStart = startTime.plusSeconds(i.toLong()).truncatedTo(java.time.temporal.ChronoUnit.SECONDS)
            val windowStart = secondStart.minusSeconds(avgWindow - 1)
            
            val metricsInAvgWindow = relevantMetrics.filter { it.timestamp > windowStart.minusMillis(1) && it.timestamp <= secondStart }
            
            timestamps.add(secondStart)
            
            // Average over avgWindow
            totalRps.add(metricsInAvgWindow.count { it.type == ScannerMetricType.SENT }.toDouble() / avgWindow)
            s200Rps.add(metricsInAvgWindow.count { it.type == ScannerMetricType.RECEIVED && it.statusCode in 200..299 }.toDouble() / avgWindow)
            s400Rps.add(metricsInAvgWindow.count { it.type == ScannerMetricType.RECEIVED && it.statusCode in 400..499 }.toDouble() / avgWindow)
            s5xxRps.add(metricsInAvgWindow.count { it.type == ScannerMetricType.RECEIVED && it.statusCode >= 500 }.toDouble() / avgWindow)
            redirectRps.add(metricsInAvgWindow.count { it.type == ScannerMetricType.RECEIVED && it.statusCode in 300..399 }.toDouble() / avgWindow)
            
            // Timeout RPS: Count SENT metrics that happened exactly timeoutThreshold seconds ago and never got a response
            val timeoutPoint = secondStart.minusSeconds(timeoutThreshold)
            val timeoutWindowStart = timeoutPoint.minusSeconds(avgWindow - 1)
            val timeoutsInWindow = relevantMetrics.count { 
                it.type == ScannerMetricType.SENT && 
                it.timestamp > timeoutWindowStart.minusMillis(1) && 
                it.timestamp <= timeoutPoint && 
                it.messageId !in receivedIds 
            }
            timeoutRps.add(timeoutsInWindow.toDouble() / avgWindow)
        }

        _scannerMonitorState.value = TimeSeriesData(
            timestamps = timestamps,
            totalRps = totalRps,
            status200Rps = s200Rps,
            status400Rps = s400Rps,
            status5xxRps = s5xxRps,
            redirectRps = redirectRps,
            timeoutRps = timeoutRps
        )
    }

    // Button Click Handlers
    var onGradeOrganizerItemsClicked: (() -> Unit)? = null
    var onBeginScanClicked: (() -> Unit)? = null

    fun updateMetrics(newState: MetricsState) {
        _metrics.value = newState
    }

    fun updateCheckbox(grade: String, selected: Boolean) {
        val current = _checkboxes.value
        _checkboxes.value = when (grade) {
            "A" -> current.copy(gradeA = selected)
            "B" -> current.copy(gradeB = selected)
            "C" -> current.copy(gradeC = selected)
            "D" -> current.copy(gradeD = selected)
            "F" -> current.copy(gradeF = selected)
            else -> current
        }
        recalculateMetrics()
    }

    private fun recalculateMetrics() {
        val currentCheckboxes = _checkboxes.value
        
        // Filtered counts
        var fA = 0; var fB = 0; var fC = 0; var fD = 0; var fF = 0
        var fs200 = 0; var fs300 = 0; var fs400 = 0; var fs500 = 0; var fsFail = 0

        // Total counts
        var tA = 0; var tB = 0; var tC = 0; var tD = 0; var tF = 0
        var ts200 = 0; var ts300 = 0; var ts400 = 0; var ts500 = 0; var tsFail = 0

        lastGradedResults.forEach { result ->
            // Update Totals
            when (result.grade) {
                "A" -> tA++
                "B" -> tB++
                "C" -> tC++
                "D" -> tD++
                "F" -> tF++
            }
            when (result.statusBucket) {
                200 -> ts200++
                300 -> ts300++
                400 -> ts400++
                500 -> ts500++
                -1 -> tsFail++
            }

            // Update Filtered
            val isSelected = when (result.grade) {
                "A" -> currentCheckboxes.gradeA
                "B" -> currentCheckboxes.gradeB
                "C" -> currentCheckboxes.gradeC
                "D" -> currentCheckboxes.gradeD
                "F" -> currentCheckboxes.gradeF
                else -> false
            }

            if (isSelected) {
                when (result.grade) {
                    "A" -> fA++
                    "B" -> fB++
                    "C" -> fC++
                    "D" -> fD++
                    "F" -> fF++
                }
                when (result.statusBucket) {
                    200 -> fs200++
                    300 -> fs300++
                    400 -> fs400++
                    500 -> fs500++
                    -1 -> fsFail++
                }
            }
        }

        val fTotalGrades = fA + fB + fC + fD + fF
        val tTotalGrades = tA + tB + tC + tD + tF

        _metrics.value = MetricsState(
            gradeA = fA.toString(),
            gradeATotal = tA.toString(),
            gradeB = fB.toString(),
            gradeBTotal = tB.toString(),
            gradeC = fC.toString(),
            gradeCTotal = tC.toString(),
            gradeD = fD.toString(),
            gradeDTotal = tD.toString(),
            gradeF = fF.toString(),
            gradeFTotal = tF.toString(),
            totalGrades = fTotalGrades.toString(),
            totalGradesTotal = tTotalGrades.toString(),
            status200s = fs200.toString(),
            status200sTotal = ts200.toString(),
            status300s = fs300.toString(),
            status300sTotal = ts300.toString(),
            status400s = fs400.toString(),
            status400sTotal = ts400.toString(),
            status500s = fs500.toString(),
            status500sTotal = ts500.toString(),
            statusFail = fsFail.toString(),
            statusFailTotal = tsFail.toString()
        )
    }

    private val json = Json { ignoreUnknownKeys = true; isLenient = true }

    fun gradeOrganizerItems() {
        viewModelScope.launch {
            logAction("Starting organizer items grading...")
            onGradeOrganizerItemsClicked?.invoke()
            performGrading()
        }
    }

    private suspend fun performGrading() {
        val items = api.organizer().items()
        if (items.isEmpty()) return

        // Clear existing notes, metrics, and grades before starting
        items.forEach { it.annotations().setNotes(null) }
        _metrics.value = MetricsState()

        val projectJsonData = readProjectJson()
        val passwords = projectJsonData.passwords
        val inScopePrefixes = projectJsonData.inScopePrefixes
        val outOfScopePrefixes = projectJsonData.outOfScopePrefixes

        // Pre-calculate expensive properties for all items once
        val itemDatas = items.map { item ->
            val request = item.request()
            val response = item.response()
            val path = request.path()
            val url = request.url()
            val method = request.method()
            val requestBody = request.bodyToString()
            val responseBody = response?.bodyToString() ?: ""
            val statusCode = response?.statusCode()?.toInt() ?: -1
            val pathPattern = getPathPattern(path)
            
            // For similarity hashes
            val params = request.parameters().filter { it.type() == HttpParameterType.URL || it.type() == HttpParameterType.BODY || it.type() == HttpParameterType.JSON }.map { it.name() }.sorted()

            object {
                val item = item
                val request = request
                val response = response
                val path = path
                val url = url
                val method = method
                val requestBody = requestBody
                val responseBody = responseBody
                val statusCode = statusCode
                val pathPattern = pathPattern
                val fullHash = "$method|$url|$requestBody|||$responseBody"
                val simHash = "$method|$pathPattern|$params|$statusCode"
            }
        }

        val staticExtensions = setOf(
            // Images
            "png", "jpeg", "jpg", "gif", "ico", "svg", "webp", "bmp", "tif", "tiff",
            // Audio/Video
            "mp3", "mp4", "wav", "avi", "mov", "mpg", "mpeg", "m4a", "m4v", "ogg", "ogv", "webm", "flac",
            // Fonts
            "woff", "woff2", "ttf", "eot", "otf",
            // Documents/Data
//            "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp", "rtf", "csv", "xml", "json",
            // Archives
            "zip", "tar", "gz", "7z", "rar", "bz2", "xz",
            // Web/Style/Scripts
            "css", "js", "map", "less", "scss",
            // Executables/System
            "exe", "dll", "bin", "iso", "dmg", "pkg", "msi"
        )

        // 16. requests with path parameters that are integers, guids, etc.
        // We need to pre-calculate path patterns for deduplication
        val pathPatternCounts = itemDatas.groupingBy { it.pathPattern }.eachCount()
        val pathPatternProcessedCounts = java.util.concurrent.ConcurrentHashMap<String, java.util.concurrent.atomic.AtomicInteger>()

        // For duplicate check, we'll need to be careful with concurrency if we were doing it during parallel processing
        // However, duplicate check (3) is based on the whole list.
        // Let's identify duplicates first to avoid thread-safety issues with a shared set during parallel processing

        // To identify which index is a duplicate of a previous index
        val isDuplicate = BooleanArray(items.size)
        val seenHashes = mutableSetOf<String>()

        // 17. Similarity Hash for reducing repeated "A" items
        val isPatternRepeat = BooleanArray(items.size)
        val patternCounts = mutableMapOf<String, Int>()

        for (i in itemDatas.indices) {
            val data = itemDatas[i]
            if (seenHashes.contains(data.fullHash)) {
                isDuplicate[i] = true
            } else {
                seenHashes.add(data.fullHash)
            }

            val count = patternCounts.getOrDefault(data.simHash, 0)
            if (count >= 1) { // Only allow the 1st occurrence to be an "A" candidate without "Repeat" status
                isPatternRepeat[i] = true
            }
            patternCounts[data.simHash] = count + 1
        }

        val results = itemDatas.indices.map { index ->
            // ... (rest of the mapping logic)
            // I'll use a more targeted replace for the end of performGrading
            viewModelScope.async(Dispatchers.Default) {
                val data = itemDatas[index]
                val item = data.item
                val request = data.request
                val response = data.response
                val url = data.url
                val method = data.method
                val path = data.path
                val pathPattern = data.pathPattern

                var grade = "B"
                val reasons = mutableListOf<String>()
                var statusBucket = 0 // 0: fail, 200, 300, 400, 500

                // 1. Items with no response: F
                if (response == null) {
                    grade = "F"
                    reasons.add("No Response")
                    statusBucket = -1
                } else {
                    val statusCode = data.statusCode
                    val responseBody = data.responseBody.lowercase()

                    if (statusCode in 200..299) statusBucket = 200
                    else if (statusCode in 300..399) statusBucket = 300
                    else if (statusCode in 400..499) statusBucket = 400
                    else if (statusCode >= 500) statusBucket = 500

                    // 2. items with a 500 response: F
                    if (statusCode >= 500) {
                        grade = "F"
                        reasons.add("${statusCode} Status")
                    }

                    // 4. 404 responses: F
                    if (statusCode == 404) {
                        grade = "F"
                        reasons.add("404 Status")
                    }

                    // 5. unauthorized responses: F
                    if (statusCode == 401 || statusCode == 403) {
                        grade = "F"
                        reasons.add("Unauthorized (${statusCode})")
                    }

                    // 6. 302, 301, 304 responses: C
                    if (statusCode == 301 || statusCode == 302 || statusCode == 304 || statusCode == 307 || statusCode == 308) {
                        if (grade != "F") {
                            grade = "C"
                            reasons.add("Redirect/Not Modified (${statusCode})")
                        }
                    }

                    // 11. 400 responses: F
                    if (statusCode == 400) {
                        grade = "F"
                        reasons.add("400 Status")
                    }

                    // 405 responses: F
                    if (statusCode == 405) {
                        grade = "F"
                        reasons.add("405 Status")
                    }

                    // 8. responses that container single page application framework template HTML
                    val spaKeywords = listOf("ng-app", "ng-version", "react-root", "_framework/blazor", "svelte-", "__next")
                    if (spaKeywords.any { responseBody.contains(it) }) {
                        reasons.add("SPA Template")
                    }

                    // 9. responses longer than 2 megabytes: F, 1-2MB: D
                    val bodyLength = response.body().length()
                    if (bodyLength > 2 * 1024 * 1024) {
                        grade = "F"
                        reasons.add("Very Large (>2MB)")
                    } else if (bodyLength > 1 * 1024 * 1024) {
                        if (grade != "F") {
                            grade = "D"
                            reasons.add("Large (1-2MB)")
                        }
                    }
                }

                // 3. duplicate requests and responses: F
                if (isDuplicate[index]) {
                    grade = "F"
                    reasons.add("Duplicate")
                }

                // 4. requests for static files
                val lowercasePath = path.lowercase()
                val extension = lowercasePath.substringAfterLast('.', "")
                if (extension in staticExtensions) {
                    grade = "F"
                    reasons.add("Static File")
                }

                // 12. requests that contain passwords
                if (passwords.isNotEmpty()) {
                    val requestContent = data.requestBody.lowercase()
                    if (passwords.any { requestContent.contains(it.lowercase()) }) {
                        grade = "F"
                        reasons.add("Contains Password")
                    }
                }

                // 13. requests that are out of scope
                val isInScope = inScopePrefixes.isEmpty() || inScopePrefixes.any { url.startsWith(it) }
                val isOutOfScope = outOfScopePrefixes.any { url.startsWith(it) }
                if (!isInScope || isOutOfScope) {
                    grade = "F"
                    reasons.add("Out of Scope")
                }

                // 14. DELETE or OPTIONS verb requests: F
                if (method == "DELETE" || method == "OPTIONS") {
                    grade = "F"
                    reasons.add("${method} Verb")
                }

                // 15. GET requests with no parameters: C
                if (method == "GET" && request.parameters().isEmpty()) {
                    if (grade != "F" && grade != "D") {
                        grade = "C"
                        reasons.add("GET No Params")
                    }
                }

                // 16. path parameter deduplication
                if (pathPattern != path) {
                    val atomicCounter = pathPatternProcessedCounts.computeIfAbsent(pathPattern) { java.util.concurrent.atomic.AtomicInteger(0) }
                    val currentCount = atomicCounter.getAndIncrement()
                    if (currentCount >= 5) {
                        if (grade != "F") {
                            grade = "D"
                            reasons.add("Path Param Deduplication")
                        }
                    }
                }

                if (reasons.isEmpty()) {
                    reasons.add("Default")
                }

                // A-Grade Boosters
                if (grade == "B") {
                    val boosterReasons = mutableListOf<String>()

                    // 1. State-Changing Methods
                    if (method == "POST" || method == "PUT" || method == "PATCH") {
                        boosterReasons.add("State-Changing Method ($method)")
                    }

                    // 2. Complex Content Types
                    val contentType = request.headerValue("Content-Type")?.lowercase() ?: ""
                    if (contentType.contains("application/json") ||
                        contentType.contains("application/xml") ||
                        contentType.contains("application/x-www-form-urlencoded")
                    ) {
                        boosterReasons.add("Complex Content-Type")
                    }


                    // 4. Reflected Input
                    if (response != null) {
                        val responseBody = data.responseBody
                        val reflectedParams = request.parameters().filter { param ->
                            val value = param.value()
                            value.length >= 3 && responseBody.contains(value)
                        }
                        if (reflectedParams.isNotEmpty()) {
                            boosterReasons.add("Reflected Parameters (${reflectedParams.joinToString(", ") { it.name() }})")
                        }
                    }

                    if (boosterReasons.isNotEmpty()) {
                        if (isPatternRepeat[index]) {
                            grade = "D"
                            reasons.add("Repeated A-Pattern (Boosters: ${boosterReasons.joinToString(", ")})")
                        } else {
                            grade = "A"
                            reasons.addAll(boosterReasons)
                        }
                    }
                }

                val reasonText = reasons.joinToString(", ")
                item.annotations().setNotes("Grade: $grade, reason: $reasonText")

                GradedItemResult(grade, statusBucket, item)
            }
        }.awaitAll()

        lastGradedResults = results
        logAction("Finished grading ${results.size} items.")
        recalculateMetrics()
    }

    private fun getPathPattern(path: String): String {
        // Replace integers with {int}
        // Replace UUIDs with {guid}
        val segments = path.split("/").map { segment ->
            when {
                segment.all { it.isDigit() } && segment.isNotEmpty() -> "{int}"
                isGuid(segment) -> "{guid}"
                else -> segment
            }
        }
        return segments.joinToString("/")
    }

    private fun isGuid(s: String): Boolean {
        return try {
            UUID.fromString(s)
            true
        } catch (e: Exception) {
            false
        }
    }

    private data class ProjectJsonData(
        val passwords: List<String> = emptyList(),
        val inScopePrefixes: List<String> = emptyList(),
        val outOfScopePrefixes: List<String> = emptyList()
    )

    private fun readProjectJson(): ProjectJsonData {
        val pathStr = myExtensionSettings.aiSessionHandlerProjectJSONPath
        if (pathStr.isBlank()) {
            logError("Project.json path is blank in settings.")
            return ProjectJsonData()
        }

        val path = Path.of(pathStr)
        if (!path.exists()) {
            logError("Project.json does not exist at $pathStr")
            return ProjectJsonData()
        }

        return try {
            val content = path.readText()
            val root = json.parseToJsonElement(content).jsonObject

            val passwords = mutableListOf<String>()
            val inScope = mutableListOf<String>()
            val outOfScope = mutableListOf<String>()
            val crawlObj = root["crawl"]?.jsonObject

            val loginObj = root["login"]?.jsonObject
            if (loginObj == null) {
                logError("Missing 'login' section in project.json")
            } else {
                val usersObj = loginObj["users"]?.jsonObject
                if (usersObj == null) {
                    logError("Missing 'users' in 'login' section of project.json")
                } else {
                    val credentialsObj = usersObj["credentials"]?.jsonObject
                    if (credentialsObj == null) {
                        logError("Missing 'credentials' in 'login/users' section of project.json")
                    } else {
                        credentialsObj["password"]?.let { p ->
                            when (p) {
                                is JsonPrimitive -> passwords.add(p.content)
                                is JsonArray -> passwords.addAll(p.mapNotNull { (it as? JsonPrimitive)?.content })
                                else -> {
                                    logError("Unable to parse 'password' field in project.json")
                                }
                            }
                        } ?: logError("Missing 'password' field in project.json")
                    }
                }
            }

            if (crawlObj == null) {
                logError("Missing 'crawl' section in project.json")
                ProjectJsonData(passwords, inScope, outOfScope)
            } else {
                crawlObj["in_scope_prefixes"]?.jsonArray?.let { arr ->
                    inScope.addAll(arr.mapNotNull { (it as? JsonPrimitive)?.content })
                } ?: logError("Missing or invalid 'in_scope_prefixes' in project.json")

                crawlObj["out_of_scope_prefixes"]?.jsonArray?.let { arr ->
                    outOfScope.addAll(arr.mapNotNull { (it as? JsonPrimitive)?.content })
                } ?: logAction("Notice: 'out_of_scope_prefixes' missing or empty in project.json")

                logAction("Project.json loaded: ${passwords.size} passwords, ${inScope.size} in-scope prefixes found.")
                ProjectJsonData(passwords, inScope, outOfScope)
            }
        } catch (e: Exception) {
            logError("Error parsing project.json: ${e.message}")
            ProjectJsonData()
        }
    }

    fun beginScan() {
        viewModelScope.launch {
            logAction("Starting scan...")
            onBeginScanClicked?.invoke()
            val currentCheckboxes = _checkboxes.value
            val itemsToScan = lastGradedResults.filter { result ->
                when (result.grade) {
                    "A" -> currentCheckboxes.gradeA
                    "B" -> currentCheckboxes.gradeB
                    "C" -> currentCheckboxes.gradeC
                    "D" -> currentCheckboxes.gradeD
                    "F" -> currentCheckboxes.gradeF
                    else -> false
                }
            }.map { it.item }

            if (itemsToScan.isNotEmpty()) {
                val auditConfig = AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS)
                val audit = api.scanner().startAudit(auditConfig)
                itemsToScan.forEach { audit.addRequestResponse(it) }
                logAction("Audit started with ${itemsToScan.size} items.")
            } else {
                logError("No items selected for scan (check your grade filters).")
            }
        }
    }
}
