package com.nickcoblentz.montoya

import MyExtensionSettings
import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.handler.*
import burp.api.montoya.core.ToolType
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.params.HttpParameterType
import kotlinx.serialization.json.*
import kotlinx.coroutines.*
import java.nio.file.Path
import kotlin.io.path.*
import java.util.concurrent.ConcurrentHashMap

class CrawlHttpHandler(
    private val api: MontoyaApi,
    private val myExtensionSettings: MyExtensionSettings,
    private val viewModel: SmartScanViewModel
) : HttpHandler {

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val json = Json { ignoreUnknownKeys = true; isLenient = true }
    private val fileLock = Any()
    private val downloadedJsFiles = ConcurrentHashMap.newKeySet<String>()
    private var lastProjectJsonPath: String? = null
    private var inScopePrefixes: List<String> = emptyList()

    override fun handleHttpRequestToBeSent(requestToBeSent: HttpRequestToBeSent): RequestToBeSentAction {
        return RequestToBeSentAction.continueWith(requestToBeSent)
    }

    override fun handleHttpResponseReceived(responseReceived: HttpResponseReceived): ResponseReceivedAction {
        if (!responseReceived.toolSource().isFromTool(ToolType.PROXY)) {
            return ResponseReceivedAction.continueWith(responseReceived)
        }

        val request = responseReceived.initiatingRequest()
        val requestResponse = HttpRequestResponse.httpRequestResponse(responseReceived.initiatingRequest(),responseReceived)

        // Existing logic for organizer
        if (request.hasParameter("x-virtue-task", HttpParameterType.COOKIE) &&
            request.parameterValue("x-virtue-task", HttpParameterType.COOKIE).contains("crawl", ignoreCase = true)
        ) {
            var millis = -1L
            requestResponse.timingData().ifPresent { timing ->
                timing.timeBetweenRequestSentAndEndOfResponse()?.let { duration ->
                    millis = duration.toMillis()
                }
            } 
            
            if (millis < 0 || millis <= 2000) {
                api.organizer().sendToOrganizer(requestResponse)
                viewModel.logAction("Captured URL sent to organizer: ${request.url()}")
            }
        }

        // New logic for JS download
        scope.launch {
            handleJsDownload(requestResponse)
        }
        
        return ResponseReceivedAction.continueWith(responseReceived)
    }

    private fun handleJsDownload(requestResponse: HttpRequestResponse) {
        val response = requestResponse.response() ?: return
        val request = requestResponse.request()
        
        // 1. Check if it's a successful JS file
        val statusCode = response.statusCode().toInt()
        if (statusCode !in 200..299) return

        val contentType = response.headerValue("Content-Type")?.lowercase() ?: ""
        val url = request.url().lowercase()
        val isJs = contentType.contains("javascript") || url.endsWith(".js") || url.contains(".js?")
        
        if (!isJs) return

        // 2. Load/Update Project JSON config and downloaded files list
        val projectJsonPathStr = myExtensionSettings.aiSessionHandlerProjectJSONPath
        if (projectJsonPathStr.isNotBlank()) {
            updateProjectConfig(projectJsonPathStr)
        }

        // 3. Check if in-scope
        val fullUrl = request.url()
        if (inScopePrefixes.none { fullUrl.startsWith(it) }) return

        // 4. Check if already downloaded
        if (downloadedJsFiles.contains(fullUrl)) return

        // 5. Download the file
        if (projectJsonPathStr.isNotBlank()) {
            downloadFile(requestResponse, projectJsonPathStr)
        }
    }

    private var cachedInScopePrefixes: List<String> = emptyList()
    private var cachedDownloadedJsFiles: Set<String> = emptySet()
    private var lastConfigCheckTime: Long = 0
    private val CONFIG_CACHE_DURATION_MS = 5000L

    private fun updateProjectConfig(projectJsonPathStr: String) {
        val now = System.currentTimeMillis()
        if (projectJsonPathStr == lastProjectJsonPath && now - lastConfigCheckTime < CONFIG_CACHE_DURATION_MS) {
            return
        }

        synchronized(fileLock) {
            // Double-checked locking
            if (projectJsonPathStr == lastProjectJsonPath && now - lastConfigCheckTime < CONFIG_CACHE_DURATION_MS) {
                return
            }
            
            val projectPath = Path.of(projectJsonPathStr)
            if (projectPath.exists()) {
                try {
                    val content = projectPath.readText()
                    val root = json.parseToJsonElement(content).jsonObject
                    val inScope = mutableListOf<String>()
                    root["crawl"]?.jsonObject?.get("in_scope_prefixes")?.jsonArray?.let { arr ->
                        inScope.addAll(arr.mapNotNull { (it as? JsonPrimitive)?.content })
                    }
                    inScopePrefixes = inScope
                    cachedInScopePrefixes = inScope

                    // Load existing downloaded files
                    val jsDir = projectPath.parent.resolve("javascript_source")
                    val newDownloadedJsFiles = ConcurrentHashMap.newKeySet<String>()
                    
                    val downloadedTxt = jsDir.resolve("downloaded_javascript.txt")
                    if (downloadedTxt.exists()) {
                        newDownloadedJsFiles.addAll(downloadedTxt.readLines().filter { it.isNotBlank() })
                    }
                    
                    val burpDownloadedTxt = jsDir.resolve("burp_downloaded_javascript.txt")
                    if (burpDownloadedTxt.exists()) {
                        newDownloadedJsFiles.addAll(burpDownloadedTxt.readLines().filter { it.isNotBlank() })
                    }

                    downloadedJsFiles.clear()
                    downloadedJsFiles.addAll(newDownloadedJsFiles)
                    cachedDownloadedJsFiles = newDownloadedJsFiles

                    lastProjectJsonPath = projectJsonPathStr
                    lastConfigCheckTime = now
                    viewModel.logAction("Project configuration updated from $projectJsonPathStr")
                } catch (e: Exception) {
                    viewModel.logError("Error parsing project.json for JS downloader: ${e.message}")
                }
            }
            else {
                viewModel.logError("Project.json does not exist at $projectJsonPathStr")
            }
        }
    }

    private fun downloadFile(requestResponse: HttpRequestResponse, projectJsonPathStr: String) {
        val request = requestResponse.request()
        val response = requestResponse.response() ?: return
        val fullUrl = request.url()

        val projectPath = Path.of(projectJsonPathStr)
        val jsDir = projectPath.parent.resolve("javascript_source")
        
        try {
            // wget style: hostname/path/filename
            val host = request.httpService().host()
            val path = request.path()
            
            // Remove query string for file path
            val pathWithoutQuery = if (path.contains("?")) path.substringBefore("?") else path
            
            // Ensure path doesn't start with / for resolve
            val relativePath = pathWithoutQuery.trimStart('/')
            
            val targetFile = jsDir.resolve(host).resolve(relativePath)
            
            // Create directories
            targetFile.parent.createDirectories()
            
            // Write content
            targetFile.writeBytes(response.body().bytes)
            viewModel.logAction("Downloaded JS file: $fullUrl to $targetFile")
            
            // Update tracking
            if (downloadedJsFiles.add(fullUrl)) {
                val burpDownloadedTxt = jsDir.resolve("burp_downloaded_javascript.txt")
                synchronized(fileLock) {
                    burpDownloadedTxt.appendText("$fullUrl\n")
                }
            }
        } catch (e: Exception) {
            viewModel.logError("Failed to download JS file $fullUrl: ${e.message}")
        }
    }
}
