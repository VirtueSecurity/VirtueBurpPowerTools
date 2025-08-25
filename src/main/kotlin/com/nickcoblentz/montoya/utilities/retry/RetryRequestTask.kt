package com.nickcoblentz.montoya.utilities

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest

class RetryRequestsTask(private val api: MontoyaApi, private var request: HttpRequest) {

    fun run() {
        if (request.hasHeader("Content-Length"))
            request = request.withUpdatedHeader("Content-Length", request.body().length().toString())
        api.http().sendRequest(request)
    }
}