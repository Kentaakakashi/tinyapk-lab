package com.kentaakakashi.memorygg.agenthost

import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.IBinder
import android.os.Process
import com.kentaakakashi.memorygg.IMemoryAgent
import java.security.MessageDigest
import java.util.UUID

class AgentHostService : Service() {
    @Volatile private var authorizedUid = -1
    private val bridge = object : IMemoryAgent.Stub() {
        override fun getInfo() = "PID=" + Process.myPid() + " UID=" + Process.myUid() + " package=" + packageName + " mode=in-process Tetris"
        override fun authorize(token: String): String {
            val expected = getSharedPreferences(PREFS, MODE_PRIVATE).getString(TOKEN_KEY, null) ?: return "DENIED: Launch Tetris first."
            if (token.isBlank() || !MessageDigest.isEqual(token.toByteArray(Charsets.UTF_8), expected.toByteArray(Charsets.UTF_8))) return "DENIED: Pairing token did not match."
            authorizedUid = Binder.getCallingUid()
            return "AUTHORIZED: caller UID $authorizedUid; target PID " + Process.myPid()
        }
        override fun selfTest() = guarded { nativeSelfTest() } ?: "DENIED: Pair the controller first."
        override fun scanFirst(value: String, type: Int) = guarded { nativeScanFirst(value, type) } ?: deniedResult()
        override fun scanNext(value: String, type: Int, condition: Int) = guarded { nativeScanNext(value, type, condition) } ?: deniedResult()
        override fun writeValue(address: Long, value: String, type: Int) = guarded { nativeWriteValue(address, value, type) } ?: "DENIED: Pair the controller first."
        override fun clearScan(): String { if (!isAuthorized()) return "DENIED: Pair the controller first."; nativeClearScan(); return "PASS: target-process scan state cleared." }
        override fun getProbeValue() = if (isAuthorized()) nativeGetTestValue() else Int.MIN_VALUE
        override fun setProbeValue(value: Int) = if (isAuthorized()) nativeSetTestValue(value) else Int.MIN_VALUE
    }
    override fun onCreate() {
        super.onCreate()
        val prefs = getSharedPreferences(PREFS, MODE_PRIVATE)
        if (prefs.getString(TOKEN_KEY, null) == null) prefs.edit().putString(TOKEN_KEY, UUID.randomUUID().toString().replace("-", "").take(12).uppercase()).apply()
    }
    override fun onBind(intent: Intent?): IBinder = bridge
    private fun isAuthorized() = Binder.getCallingUid() == authorizedUid
    private inline fun guarded(block: () -> String): String? {
        if (!isAuthorized()) return null
        return try { block() } catch (t: Throwable) { "ERROR: " + t.javaClass.simpleName + ": " + (t.message ?: "unknown") }
    }
    private fun deniedResult() = "{\"ok\":false,\"message\":\"Pair the controller with Tetris first.\",\"count\":0,\"matches\":[]}"
    private external fun nativeSelfTest(): String
    private external fun nativeScanFirst(value: String, type: Int): String
    private external fun nativeScanNext(value: String, type: Int, condition: Int): String
    private external fun nativeWriteValue(address: Long, value: String, type: Int): String
    private external fun nativeClearScan()
    private external fun nativeGetTestValue(): Int
    private external fun nativeSetTestValue(value: Int): Int
    companion object {
        private const val PREFS = "memorygg_agent_pairing"
        private const val TOKEN_KEY = "pairing_token"
        init { System.loadLibrary("memorygg") }
    }
}
