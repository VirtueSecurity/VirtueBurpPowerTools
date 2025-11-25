package com.nickcoblentz.montoya

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.scanner.AuditResult
import burp.api.montoya.scanner.ConsolidationAction
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import burp.api.montoya.scanner.scancheck.PassiveScanCheck
import burp.api.montoya.scanner.scancheck.ScanCheckType
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.util.regex.Pattern

class DisposableEmailScanChecker(private val api: MontoyaApi) : PassiveScanCheck {

    companion object {
        const val PLUGIN_NAME = "Disposable Email Passive Scanner Checker"
        const val BLOCKLIST_URL = "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/refs/heads/main/disposable_email_blocklist.conf"
    }

    private val disposableDomains: MutableSet<String> = HashSet()
    private val emailPattern = Pattern.compile("[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})")
    private var logger = MontoyaLogger(api, LogLevel.DEBUG)

    init {

        logger.debugLog("Starting $PLUGIN_NAME...")
        Thread.ofVirtual().start {
            loadBlocklist()
        }
        Thread { loadBlocklist() }.start()
        api.scanner().registerPassiveScanCheck(this, ScanCheckType.PER_REQUEST)
        logger.debugLog("...Finished $PLUGIN_NAME")
    }

    private fun loadBlocklist() {

        logger.debugLog("Fetching blocklist from: $BLOCKLIST_URL")

        val client = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build()

        val request = HttpRequest.newBuilder()
            .uri(URI.create(BLOCKLIST_URL))
            .GET()
            .build()

        // This downloads the file directly to disk
        val response = client.send(request, HttpResponse.BodyHandlers.ofString())

        if (response.statusCode() == 200) {
            println("Found:\n${response.body()}")
        } else {
            println("Failed to download. Status code: ${response.statusCode()}")
        }

        val domains = response.body().lines()
        .map { it.trim() }
        .filter { it.isNotEmpty() }.toSet()

        disposableDomains.addAll(domains)

        api.logging().logToOutput("Successfully loaded ${domains.size} disposable domains.")

    }

    override fun checkName() = PLUGIN_NAME

    override fun doCheck(baseRequestResponse: HttpRequestResponse): AuditResult {
        // If the list hasn't loaded yet, skip scanning to avoid false negatives or errors
        if (disposableDomains.isEmpty()) {
            return AuditResult.auditResult(emptyList())
        }

        val responseBody = baseRequestResponse.response().bodyToString()
        val matcher = emailPattern.matcher(responseBody)
        val detectedEmails = mutableSetOf<String>()
        val detectedDomains = mutableSetOf<String>()

        while (matcher.find()) {
            val fullEmail = matcher.group(0)
            val domain = matcher.group(1).lowercase()

            if (isDisposable(domain)) {
                detectedEmails.add(fullEmail)
                detectedDomains.add(domain)
            }
        }

        if (detectedEmails.isEmpty()) {
            return AuditResult.auditResult(emptyList())
        }

        // Create a unified list for the issue description
        val issueDescription = buildString {
            append("<p>The response contains the following email addresses that belong to known disposable email providers:</p>")
            append("<ul>")
            detectedEmails.forEach { email -> append("<li>$email</li>") }
            append("</ul>")
            append("<p><b>Observed Disposable Domains:</b></p>")
            append("<ul>")
            detectedDomains.forEach { d -> append("<li>$d</li>") }
            append("</ul>")
            append("<p>These domains were matched against the remote blocklist.</p>")
        }

        // Create the Scan Issue
        val issue = AuditIssue.auditIssue(
            "Disposable Email Address Disclosed",
            issueDescription,
            "", // Severity
            baseRequestResponse.request().url(),     // Confidence
            AuditIssueSeverity.MEDIUM, // Background
            AuditIssueConfidence.CERTAIN,
            "",
            "",
            AuditIssueSeverity.MEDIUM,
            baseRequestResponse,
            baseRequestResponse
        )

        return AuditResult.auditResult(listOf(issue))
    }

    override fun consolidateIssues(
        existingIssue: AuditIssue,
        newIssue: AuditIssue
    ): ConsolidationAction? {
        return if (newIssue.name() == existingIssue.name() && newIssue.baseUrl() == existingIssue.baseUrl() && newIssue.detail() == existingIssue.detail()) {
            ConsolidationAction.KEEP_EXISTING
        } else {
            ConsolidationAction.KEEP_BOTH
        }
    }

    private fun isDisposable(domain: String): Boolean {
        var currentDomain = domain

        while (currentDomain.contains(".")) {
            if (disposableDomains.contains(currentDomain)) {
                return true
            }
            // Strip the first subdomain (e.g., sub.example.com -> example.com)
            val nextDotIndex = currentDomain.indexOf('.')
            if (nextDotIndex == -1) break
            currentDomain = currentDomain.substring(nextDotIndex + 1)
        }

        return false
    }


}