package com.nickcoblentz.montoya.utils

import burp.api.montoya.MontoyaApi
import burp.api.montoya.ui.hotkey.HotKeyEvent
import burp.api.montoya.ui.hotkey.HotKeyHandler

class CopyRequestResponseHotKeyProvider(private val _api : MontoyaApi, private val _stripHeaders : Boolean, private val _copyMode : CopyRequestResponseHandler.CopyMode) : HotKeyHandler {
    private val _copyHandler = CopyRequestResponseHandler(_api)

    override fun handle(event: HotKeyEvent?) {
        event?.let {
            if(it.messageEditorRequestResponse().isPresent) {
                val requestResponse = it.messageEditorRequestResponse().get()
                _copyHandler.copyToClipboard(
                    _copyHandler.copyItem(requestResponse.requestResponse(), _stripHeaders, _copyMode)
                )
            }
        }
    }
}