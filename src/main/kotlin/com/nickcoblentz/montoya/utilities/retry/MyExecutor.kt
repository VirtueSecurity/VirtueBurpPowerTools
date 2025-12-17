package com.nickcoblentz.montoya.utilities

import MyExtensionSettings
import burp.api.montoya.MontoyaApi
import com.nickcoblentz.montoya.LogLevel
import com.nickcoblentz.montoya.MontoyaLogger
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Semaphore

class MyExecutor (
    val api: MontoyaApi,
    var myExtensionSettings: MyExtensionSettings ){

    fun concurrentRequestLimit(): Int = myExtensionSettings.requestLimit


    private val executorService: ExecutorService = Executors.newVirtualThreadPerTaskExecutor()
    private val logger : MontoyaLogger = MontoyaLogger(api,LogLevel.DEBUG)
    private var queuedRequests = 0
    private var currentLimit = 10

    var semaphore = Semaphore(10)
        public get
        private set



    fun runTask(retryRequestTask: RetryRequestsTask) {
        if(myExtensionSettings.limitConcurrentRequestsSetting && currentLimit!=concurrentRequestLimit()) {
            semaphore=Semaphore(concurrentRequestLimit())
            currentLimit = concurrentRequestLimit()
        }

        executorService.submit {
            queuedRequests++
            printLoggingInfo()

            if(myExtensionSettings.limitConcurrentRequestsSetting)
                semaphore.acquire()

            retryRequestTask.run()

            if(myExtensionSettings.limitConcurrentRequestsSetting)
                semaphore.release()

            printLoggingInfo()
            queuedRequests--
        }
    }

    fun runTask(taskFunction : () -> Unit) {
        if(myExtensionSettings.limitConcurrentRequestsSetting && currentLimit!=concurrentRequestLimit()) {
            semaphore=Semaphore(concurrentRequestLimit())
            currentLimit = concurrentRequestLimit()
        }

        executorService.submit {
            queuedRequests++
            printLoggingInfo()

            if(myExtensionSettings.limitConcurrentRequestsSetting)
                semaphore.acquire()

            taskFunction()

            if(myExtensionSettings.limitConcurrentRequestsSetting)
                semaphore.release()

            printLoggingInfo()
            queuedRequests--
        }
    }

    fun printLoggingInfo() {
        if(myExtensionSettings.limitConcurrentRequestsSetting) {
            logger.debugLog("Concurrent Request Limit = ${concurrentRequestLimit()}")
        }
        else {
            logger.debugLog("No concurrent request limits")
        }

        logger.debugLog("Semaphore: Queue Length = ${semaphore.queueLength}, Available Permits = ${semaphore.availablePermits()}")
        logger.debugLog("Queued Requests: $queuedRequests")
    }


}