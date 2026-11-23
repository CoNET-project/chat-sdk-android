package network.conet.chat.nativekey

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Exhaustive interruption of the window resume (2026-11-17, independent review main5: "every write point, not only the writes").
 * Every mutating file operation of the resume (write, rename, delete, including the audit rows and the intent and marker removals) is
 * numbered in a recorded run. For each number the resume is stopped just before and just after that operation, and the next launch is run.
 * The invariants checked after each launch:
 *  - no content is lost: every byte string held before the resume is still held somewhere (intent, marker and audit excepted);
 *  - no roll-forward: the audit never gains a roll_forward row, and the state is never the new account;
 *  - the old account is either in place (every fixed name holds its old bytes, the record opens to the original address, the marker is gone),
 *    or the marker stays (rollback_pending) and nothing is removed.
 * A second interruption during the next launch is then checked the same way (every second point, for every first point).
 */
class ExhaustiveInterruptTest {
    private val oldPhrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val newPhrase = "legal winner thank year wave sausage worth useful legal winner thank yellow"
    private val wrap = NativeTestWrap()
    private val oldKey by lazy { checkNotNull(MnemonicDerivation.deriveKey(oldPhrase)) }
    private val oldEoa by lazy { checkNotNull(WalletAddress.fromPrivateKey(oldKey)) }

    @Before fun newLaunch() {
        NativeWalletVault.resetLaunchForTests()
    }

    /** Counts and optionally stops at the [crashAt]-th mutating operation (before or after it runs). */
    private class OpFiles(val inner: NativeTestFiles) : VaultFiles {
        var crashAt = -1
        var before = false
        var ops = 0
        private fun gate(action: () -> Unit) {
            val idx = ops++
            if (idx == crashAt && before) throw NativeTestCrash()
            action()
            if (idx == crashAt && !before) throw NativeTestCrash()
        }
        override fun read(name: String): ByteArray? = inner.read(name)
        override fun write(name: String, bytes: ByteArray) = gate { inner.write(name, bytes) }
        override fun delete(name: String) = gate { inner.delete(name) }
        override fun names(): List<String> = inner.names()
        override fun rename(from: String, to: String) = gate { inner.rename(from, to) }
    }

    private fun digest(b: ByteArray): String = java.security.MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    /** The stopped write: the old account, then the record of the new account written and the write stopped right after REC. */
    private fun stopped(): Pair<Map<String, ByteArray>, Map<String, ByteArray>> {
        val files = NativeTestFiles()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(oldEoa, oldKey, oldPhrase))
        val old = listOf(NativeWalletVault.REC, NativeWalletVault.MNEM, NativeWalletVault.MARK, NativeWalletVault.COMMIT)
            .associateWith { files.map[it]!!.copyOf() }
        val newKey = checkNotNull(MnemonicDerivation.deriveKey(newPhrase))
        files.crashAfterWrite = NativeWalletVault.REC
        try {
            NativeWalletVault(wrap, files).syncPhrase(checkNotNull(WalletAddress.fromPrivateKey(newKey)), newKey, newPhrase)
        } catch (_: NativeTestCrash) {
        }
        files.crashAfterWrite = null
        return old to files.map.mapValues { it.value.copyOf() }
    }

    private fun copyOf(map: Map<String, ByteArray>): NativeTestFiles {
        val f = NativeTestFiles()
        map.forEach { (k, v) -> f.map[k] = v.copyOf() }
        return f
    }

    private fun digests(map: Map<String, ByteArray>): Set<String> =
        map.filterKeys { it != NativeWalletVault.INTENT && it != NativeWalletVault.PENDING && it != NativeWalletVault.AUDIT }
            .values.map { digest(it) }.toSet()

    private fun auditText(files: NativeTestFiles): String = files.map[NativeWalletVault.AUDIT]?.let { String(it, Charsets.UTF_8) } ?: ""

    /** The invariants after a launch; [before] is the stopped state, [old] the old bytes per fixed name. */
    private fun checkAfter(tag: String, files: NativeTestFiles, before: Map<String, ByteArray>, old: Map<String, ByteArray>) {
        assertFalse("$tag: no roll-forward row", auditText(files).contains("\"reason\":\"roll_forward\""))
        val lost = digests(before) - digests(files.map)
        assertTrue("$tag: nothing lost (missing digests ${lost.size})", lost.isEmpty())
        val pending = files.map.containsKey(NativeWalletVault.PENDING)
        if (!pending) {
            val state = NativeWalletVault(wrap, files).state()
            assertTrue("$tag: old account in place, state $state", state is NativeWalletVault.State.Ready)
            assertEquals("$tag: original address", oldEoa.lowercase(), (state as NativeWalletVault.State.Ready).eoa.lowercase())
            old.forEach { (name, bytes) -> assertArrayEquals("$tag: $name is old", bytes, files.map[name]) }
            assertFalse("$tag: intent gone", files.map.containsKey(NativeWalletVault.INTENT))
        }
    }

    /** Runs the first launch with the [k]-th mutating operation stopped (before it, or after it). Returns the operation count and the bytes. */
    private fun runFirst(k: Int, before: Boolean, stop: Map<String, ByteArray>): Pair<Int, NativeTestFiles> {
        val inner = copyOf(stop)
        val op = OpFiles(inner)
        op.crashAt = k
        op.before = before
        NativeWalletVault.resetLaunchForTests()
        try {
            NativeWalletVault(wrap, op).settleForWrite()
        } catch (_: NativeTestCrash) {
        }
        return op.ops to inner
    }

    /** The number of mutating operations of one uninterrupted first launch. */
    private fun countFirst(stop: Map<String, ByteArray>): Int {
        val op = OpFiles(copyOf(stop))
        NativeWalletVault.resetLaunchForTests()
        NativeWalletVault(wrap, op).settleForWrite()
        return op.ops
    }

    @Test fun everyPointOfTheFirstLaunchIsSurvivedByTheNextLaunch() {
        val (old, stop) = stopped()
        val n = countFirst(stop)
        assertTrue("the resume has mutating steps ($n)", n > 5)
        println("EXH1 mutating steps of the first launch = $n")
        for (k in 0 until n) for (before in listOf(true, false)) {
            val tag = "k=$k ${if (before) "before" else "after"}"
            val (_, files) = runFirst(k, before, stop)
            NativeWalletVault.resetLaunchForTests()
            NativeWalletVault(wrap, files).settleForWrite() // the next launch, uninterrupted
            checkAfter(tag, files, stop, old)
        }
    }

    // A second interruption during the next launch, at every point of that launch, after every point of the first launch.
    @Test fun everySecondPointAfterEveryFirstPointIsSurvived() {
        val (old, stop) = stopped()
        val n = countFirst(stop)
        var cases = 0
        for (k in 0 until n) for (before in listOf(true, false)) {
            val (_, mid) = runFirst(k, before, stop)
            val midMap = mid.map.mapValues { it.value.copyOf() }
            val m = countFirst(midMap)
            for (j in 0 until m) for (before2 in listOf(true, false)) {
                val inner = copyOf(midMap)
                val op = OpFiles(inner)
                op.crashAt = j
                op.before = before2
                NativeWalletVault.resetLaunchForTests()
                try {
                    NativeWalletVault(wrap, op).settleForWrite()
                } catch (_: NativeTestCrash) {
                }
                NativeWalletVault.resetLaunchForTests()
                NativeWalletVault(wrap, inner).settleForWrite()
                checkAfter("k=$k before=$before j=$j before2=$before2", inner, stop, old)
                cases++
            }
        }
        println("EXH2 first=$n cases=$cases")
    }
}
