package network.conet.chat.nativekey

import java.io.File

/** Per-case result lines for a vector run, written only when VECTOR_RESULT_LOG names a file (a report aid; no effect on the assertions). */
internal object VectorResultLog {
    private val path: String? = System.getenv("VECTOR_RESULT_LOG")
    fun record(group: String, id: String, problems: List<String>) {
        val p = path ?: return
        File(p).appendText("$group $id ${if (problems.isEmpty()) "PASS" else "FAIL " + problems.joinToString("; ")}\n")
    }
}
