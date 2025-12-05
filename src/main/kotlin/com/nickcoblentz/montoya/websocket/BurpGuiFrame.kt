package com.nickcoblentz.montoya.websocket

import java.awt.Dimension
import java.awt.Toolkit
import javax.swing.JFrame

class BurpGuiFrame(title: String) {
    val frame = JFrame(title)

    init {
        val toolkit: Toolkit = Toolkit.getDefaultToolkit()
        val screenSize: Dimension = toolkit.screenSize
        val frameWidth = (screenSize.width * 0.50).toInt()
        val frameHeight = (screenSize.height * 0.50).toInt()
        frame.setSize(frameWidth, frameHeight)
        frame.setLocationRelativeTo(null) // Center the window on the screen
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE) // Close only this window
    }

    fun showFrame() {
        frame.isVisible = true
    }
}