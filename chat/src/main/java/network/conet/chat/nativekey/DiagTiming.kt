package network.conet.chat.nativekey

/**
 * Diagnostic timing only (diag2, 2026-11-16). Logs the thread name, the elapsed milliseconds, a label and a code. Never logs content, parameters or keys.
 * Kept out of the ShellRecord file, which must not contain a logging token (ShellRecordTest).
 */
internal object DiagTiming {
    fun now(): Long = System.nanoTime()

    fun log(label: String, startNs: Long, code: String = "") {
        val ms = (System.nanoTime() - startNs) / 1_000_000
        android.util.Log.i("ConetDiag", "$label thread=${Thread.currentThread().name} ms=$ms code=$code")
    }
}
