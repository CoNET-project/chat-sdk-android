package network.conet.chat.identity

import org.json.JSONArray
import org.json.JSONObject
import java.util.TreeSet

/**
 * The credential field names (CRED, 25.52AQ.2, r3co; the extension of five names confirmed by R649, r3cq 25.52AS.2). For the commands in
 * [COMMANDS] a credential field is refused with `key_over_bridge_refused` before the gate (25.52AT.1 step 2). The refusal names the field, and
 * never returns or logs a value. Matching is on the canonical form N ([IdentityProvisionContract.normalize]), case-insensitively, at any depth.
 */
object CredFields {
    /** The commands to which CRED applies (25.52AQ.2). Other commands keep their own rules. */
    val COMMANDS: Set<String> = setOf(
        "pgpRestore", "pgpRestoreEvaluate", "pgpDecryptInbound", "pgpIdentityCreate", "provisionIdentity", "init",
    )

    /** CRED: the names of [IdentityProvisionContract.FORBIDDEN_KEYS]. The identity command's full forbidden set is this list (25.52AQ.2 c). */
    val NAMES: List<String> get() = IdentityProvisionContract.FORBIDDEN_KEYS

    private val normalized: Set<String> by lazy { NAMES.map { IdentityProvisionContract.normalize(it).lowercase() }.toSet() }

    /**
     * The credential field names in [body] (an object's keys, and the keys of the objects inside arrays, at any depth). Unique, in UTF-8 byte
     * order. Values are never read.
     */
    fun namesIn(body: JSONObject): List<String> {
        val found = TreeSet<String>(BYTE_ORDER)
        collect(body, found)
        return found.toList()
    }

    /** The field names that refuse [command] before the gate: empty when the command has no CRED rule or the body carries no credential field. */
    fun refusalNames(command: String, body: JSONObject): List<String> =
        if (command in COMMANDS) namesIn(body) else emptyList()

    private fun collect(node: Any?, out: MutableSet<String>) {
        when (node) {
            is JSONObject -> for (key in node.keys().asSequence()) {
                if (IdentityProvisionContract.normalize(key).lowercase() in normalized) out += key
                collect(node.opt(key), out)
            }
            is JSONArray -> for (i in 0 until node.length()) collect(node.opt(i), out)
        }
    }

    private val BYTE_ORDER = Comparator<String> { a, b -> compareBytes(a.toByteArray(Charsets.UTF_8), b.toByteArray(Charsets.UTF_8)) }

    private fun compareBytes(a: ByteArray, b: ByteArray): Int {
        for (i in 0 until minOf(a.size, b.size)) {
            val d = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
            if (d != 0) return d
        }
        return a.size - b.size
    }
}
