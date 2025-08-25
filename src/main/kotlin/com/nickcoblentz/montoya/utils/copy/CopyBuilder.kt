package com.nickcoblentz.montoya.utils

class CopyBuilder {
    val builder = StringBuilder()

    fun withUrlHTTP(url : String) = apply {surroundWithBold(url)}
    fun withUrlWS(url : String, direction: String) = apply {surroundWithBold("$url ($direction)")}
    fun withHTTP(requestOrResponse: String) = apply {surroundWithHTTPCodeBLock(requestOrResponse)}
    fun withWS(message: String) = apply {surroundWithCodeBLock(message)}
    override fun toString() = builder.toString()


    private fun surroundWithBold(s: String) = apply { builder.append("**$s**\n\n") }
    private fun surroundWithHTTPCodeBLock(s: String) = apply { surroundWithCodeBLock(s,"http") }
    private fun surroundWithCodeBLock(s: String, syntax: String="") = apply {builder.append(String.format("```$syntax\n%s\n```\n\n", s.trim { it <= ' ' }))}
}