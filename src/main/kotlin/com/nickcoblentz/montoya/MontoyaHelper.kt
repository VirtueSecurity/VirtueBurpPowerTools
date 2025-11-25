package com.nickcoblentz.montoya

import java.awt.Frame
import javax.swing.*


fun registerGlobalHotKey(keyStroke : KeyStroke, actionKey : String, myAction : Action) {
    findBurpRootPane()?.let { rootPane ->
        val inputMap: InputMap = rootPane.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
        val actionMap: ActionMap = rootPane.actionMap

        inputMap.put(keyStroke, actionKey)
        actionMap.put(actionKey, myAction)
    }
}


fun findBurpRootPane(): JRootPane? {
    for (frame in Frame.getFrames()) {
        if (frame.isVisible && frame is JFrame) {
            // A heuristic search for the main Burp window
            // based on the frame title or content structure.
            // This is the most brittle part of the hack.
            if (frame.getTitle().contains("Burp Suite")) {
                return frame.getRootPane()
            }
        }
    }
    return null
}