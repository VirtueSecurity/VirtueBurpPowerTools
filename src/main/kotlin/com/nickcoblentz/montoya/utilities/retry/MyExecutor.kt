package com.nickcoblentz.montoya.utilities

import MyExtensionSettings
import burp.api.montoya.MontoyaApi
import com.nickcoblentz.montoya.LogLevel
import com.nickcoblentz.montoya.MontoyaLogger
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.sync.withPermit
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger

class MyExecutor(
    val api: MontoyaApi,
    var myExtensionSettings: MyExtensionSettings
) {

    fun concurrentRequestLimit(): Int = myExtensionSettings.requestLimit

    private val executorService = Executors.newVirtualThreadPerTaskExecutor()
    private val dispatcher = executorService.asCoroutineDispatcher()
    val customScope = CoroutineScope(dispatcher + SupervisorJob())
    private val logger: MontoyaLogger = MontoyaLogger(api, LogLevel.DEBUG)
    private val queuedRequests = AtomicInteger(0)
    private var currentLimit = 10

    private val semaphoreMutex = Mutex()
    var semaphore = Semaphore(10)
        private set

    fun runTask(retryRequestTask: RetryRequestsTask) = runTask { retryRequestTask.run() }

    fun runTask(taskFunction: suspend () -> Unit) {
        customScope.launch {
            try {
                checkLimit()
                queuedRequests.incrementAndGet()
                printLoggingInfo()

                val useLimit = myExtensionSettings.limitConcurrentRequestsSetting
                val currentSemaphore = semaphoreMutex.withLock { semaphore }

                if (useLimit) {
                    currentSemaphore.withPermit {
                        taskFunction()
                    }
                } else {
                    taskFunction()
                }
            } finally {
                printLoggingInfo()
                queuedRequests.decrementAndGet()
            }
        }
    }

    private suspend fun checkLimit() {
        val targetLimit = concurrentRequestLimit().coerceAtLeast(1)
        if (myExtensionSettings.limitConcurrentRequestsSetting && currentLimit != targetLimit) {
            semaphoreMutex.withLock {
                if (currentLimit != targetLimit) {
                    semaphore = Semaphore(targetLimit)
                    currentLimit = targetLimit
                }
            }
        }
    }

    fun shutdown() {
        customScope.cancel()
        executorService.shutdown()
    }

    fun printLoggingInfo() {
        val limitMsg = if (myExtensionSettings.limitConcurrentRequestsSetting) {
            "Concurrent Request Limit = ${concurrentRequestLimit()}"
        } else {
            "No concurrent request limits"
        }
        logger.debugLog(limitMsg)
        logger.debugLog("Semaphore: Available Permits = ${semaphore.availablePermits}")
        logger.debugLog("Queued Requests: ${queuedRequests.get()}")
    }
}