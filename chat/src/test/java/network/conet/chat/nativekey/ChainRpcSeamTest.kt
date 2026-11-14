package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Busy seam (r3eb CB.1, r3ed CD.1 condition 2; PM R727): `PgpRestoreBridge.chainRpc` is an internal var whose default is the production HTTP
 * transport, and no production source (main or qa) assigns it. A source audit: it fails if a production source assigns the seam, or if the
 * declaration changes. Test sources may assign it: the busy test does, in the test target.
 */
class ChainRpcSeamTest {
    private val roots = listOf(File("src/main/java"), File("src/qa/java"))
    private val assignment = Regex("""\bchainRpc\s*=(?!=)""")

    private fun productionFiles(): List<File> =
        roots.flatMap { root -> root.walkTopDown().filter { it.isFile && it.name.endsWith(".kt") }.toList() }

    @Test
    fun theSeamIsAnInternalVarWithTheHttpDefault() {
        val decl = File("src/main/java/network/conet/chat/nativekey/PgpRestoreBridge.kt").readLines().single { it.contains("var chainRpc") }
        assertTrue(decl, decl.contains("internal var chainRpc"))
        assertTrue(decl, decl.contains("AddressPgpRead.HttpRpc(ep.url, ep.timeoutMs)"))
    }

    @Test
    fun noProductionSourceAssignsTheSeam() {
        val hits = productionFiles().flatMap { f ->
            f.readLines().mapIndexedNotNull { i, line ->
                if (assignment.containsMatchIn(line) && !line.contains("internal var chainRpc")) "${f.path}:${i + 1}" else null
            }
        }
        assertEquals("production assignments of chainRpc", emptyList<String>(), hits)
    }

    @Test
    fun theSeamIsUsedInProductionOnlyByTheRestoreMachine() {
        val files = productionFiles().flatMap { f -> f.readLines().filter { it.contains("chainRpc") }.map { f.name } }
        assertEquals(listOf("PgpRestoreBridge.kt", "PgpRestoreBridge.kt"), files)
    }
}
