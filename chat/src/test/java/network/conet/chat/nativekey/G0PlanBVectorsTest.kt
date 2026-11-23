package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.io.IOException
import java.security.MessageDigest

/**
 * The G0 plan B vectors (identity-clear-g0-plan-b-vectors.v4.json, 20 cases, v4), driven through the production decision code in the order the
 * module uses: the key-only precheck, the gate step (clearGateStep), the handler (IdentityClear.clear), and the cold-start redo (redoIfInterrupted over
 * redoScopeSafeReading). The module's Context-bound reads are replaced by fakes that can fail. Synthetic accounts X, Y, Z.
 */
class G0PlanBVectorsTest {
    private val file = File("../spec/identity-clear-g0-plan-b-vectors.v4.json")
    private val doc = JSONObject(file.readText(Charsets.UTF_8))
    private val x = "0x" + "a".repeat(40)
    private val y = "0x" + "b".repeat(40)
    private val z = "0x" + "c".repeat(40)
    private fun acct(label: String?): String? = when (label) { null -> null; "X" -> x; "Y" -> y; "Z" -> z; else -> throw IllegalArgumentException(label) }
    private fun bare(e: String) = e.removePrefix("0x")
    private val wrap = NativeTestWrap()

    @Test
    fun theFileIsTheDeliveredOne() {
        val sha = MessageDigest.getInstance("SHA-256").digest(file.readBytes()).joinToString("") { "%02x".format(it) }
        assertEquals("ec3f0ce34dad", sha.take(12))
        assertEquals(20, doc.getJSONArray("cases").length())
    }

    @Test
    fun everyCaseMatchesItsExpectation() {
        val failures = mutableListOf<String>()
        val list = doc.getJSONArray("cases")
        for (i in 0 until list.length()) {
            val c = list.getJSONObject(i)
            val problems = if (c.getString("phase") == "coldStart") runCold(c) else runManual(c)
            VectorResultLog.record("g0PlanB", c.getString("id"), problems)
            failures += problems.map { "${c.getString("id")}: $it" }
        }
        assertEquals(emptyList<String>(), failures)
    }

    /**
     * Spec section 3: gate-state G0-CLR-PENDING / G1-CLR-PENDING carry `code: ok`, which is the gate's pass to the handler, not the final answer.
     * GateStateVectorsTest models it as a constant ("ok") and never calls the handler. Here the final answers are decided by the production steps:
     * G0 with an account marker does not answer ok (GB-01); without a marker the gate answers as before (G0-CLR-NOPENDING no_key, G1-CLR-NOPENDING
     * not_ready), unchanged by plan B.
     */
    @Test
    fun theGateLayerOkOfClrPendingIsNotTheFinalAnswerAndTheNoPendingAnswersAreUnchanged() {
        assertEquals(ClearGateStep.INCOMPLETE, clearGateStep(g2 = false, g0 = true, owner = PendingOwner.Owned(x), currentEoa = null))
        assertEquals(ClearGateStep.RESUME, clearGateStep(g2 = false, g0 = true, owner = PendingOwner.NoAccount, currentEoa = null))
        assertEquals(ClearGateStep.RESUME, clearGateStep(g2 = false, g0 = false, owner = PendingOwner.Owned(x), currentEoa = x))
        assertEquals(ClearGateStep.GATE, clearGateStep(g2 = false, g0 = true, owner = PendingOwner.Absent, currentEoa = null))
        assertEquals("no_key", NoKeyGate.answerFor("clearIdentity", NoKeyGate.Gate.G0))
        assertEquals("not_ready", NoKeyGate.answerFor("clearIdentity", NoKeyGate.Gate.G1))
    }

    private class Counter { var erased = 0; var migrationChecks = 0 }

    private fun markerFiles(state: JSONObject): NativeTestFiles {
        val files = NativeTestFiles()
        val m = state.getJSONObject("marker")
        when (m.getString("kind")) {
            "owned" -> assertTrue(ClearFlagFiles(files).setClearPending(acct(m.getString("eoa"))))
            "noAccount" -> assertTrue(ClearFlagFiles(files).setClearPending(null))
            "unknown" -> files.map[ClearFlagFiles.CLEAR_PENDING] = "1".toByteArray(Charsets.UTF_8)
            "absent", "flagUnreadable" -> Unit // flagUnreadable: the file set is wrapped below so that the clear_pending read throws
            else -> throw IllegalArgumentException("marker kind")
        }
        return files
    }

    private fun markerWord(files: NativeTestFiles): String = when (ClearFlagFiles(files).clearPendingOwner()) {
        PendingOwner.Absent -> "absent"
        else -> "kept"
    }

    /** The file set the product reads: the clear_pending read throws for a flagUnreadable marker, and identity_cleared for identityCleared unreadable. */
    private fun readSet(files: NativeTestFiles, flagUnreadable: Boolean, clearedUnreadable: Boolean): VaultFiles =
        if (!flagUnreadable && !clearedUnreadable) files else object : VaultFiles by files {
            override fun read(name: String): ByteArray? =
                if ((flagUnreadable && name == ClearFlagFiles.CLEAR_PENDING) || (clearedUnreadable && name == ClearFlagFiles.IDENTITY_CLEARED)) throw IOException("read fault")
                else files.read(name)
            override fun exists(name: String): Boolean =
                if ((flagUnreadable && name == ClearFlagFiles.CLEAR_PENDING) || (clearedUnreadable && name == ClearFlagFiles.IDENTITY_CLEARED)) throw IOException("read fault")
                else files.exists(name)
        }

    private fun check(out: MutableList<String>, what: String, want: Any?, got: Any?) {
        if (want != got) out += "$what $got != $want"
    }

    private fun runManual(c: JSONObject): List<String> {
        val out = mutableListOf<String>()
        val state = c.getJSONObject("state")
        val expect = c.getJSONObject("expect")
        val files = markerFiles(state)
        val current = acct(if (state.isNull("currentAccount")) null else state.getString("currentAccount"))
        val kept = state.optBoolean("publishedCopiesKept")
        // identity_cleared: set / unset / unreadable (v2). A case without the field that keeps the published copy is a device after a completed clear.
        val clearedState = if (state.has("identityCleared")) state.getString("identityCleared") else if (kept) "set" else "unset"
        if (clearedState == "set") assertTrue(ClearFlagFiles(files).setIdentityCleared())
        if (clearedState == "invalid") files.map[ClearFlagFiles.IDENTITY_CLEARED] = "damaged".toByteArray(Charsets.UTF_8)
        val before = files.map.toMap()
        val counter = Counter()
        val flagUnreadable = state.getJSONObject("marker").getString("kind") == "flagUnreadable"
        val readFiles: VaultFiles = readSet(files, flagUnreadable, clearedState == "unreadable")
        val flagsRead = ClearFlagFiles(readFiles)

        // The key-only precheck, as the module computes it: a private-key-only account is the current account with the kept published copy, no phrase.
        // walletEntities keyOnlyAccountRestored (GB-P3e): a private-key-only account was restored after the clear, so the vault holds a key record; the
        // wallet is Locked with a ready session, so there is no current account and the gate is G2.
        val vaultFiles = NativeTestFiles()
        if (state.optString("walletEntities") == "keyOnlyAccountRestored") {
            val phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            val key = checkNotNull(MnemonicDerivation.deriveKey(phrase))
            val eoa = checkNotNull(WalletAddress.fromPrivateKey(key)).lowercase()
            assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, vaultFiles).importKey(eoa, key.copyOf()))
        }
        val vault = NativeWalletVault(wrap, vaultFiles)
        val setStore = MnemonicSetStore(java.nio.file.Files.createTempDirectory("g0b").toFile())
        val legacy = when {
            !kept -> NativeWalletVault.PublishedWalletCopy.Absent
            state.has("publishedCopiesReadable") && !state.getBoolean("publishedCopiesReadable") -> NativeWalletVault.PublishedWalletCopy.Unknown
            else -> NativeWalletVault.PublishedWalletCopy.Present
        }
        val keyOnlyNow = vault.keyWithoutPhraseFor(current, setStore, legacy)
        val owner = flagsRead.clearPendingOwner()
        val vaultNoKey = vault.state() is NativeWalletVault.State.NoKey && vault.keyRecordsAbsent()
        var answer: String
        var reason: String? = null
        val g2 = current != null || state.optBoolean("sessionReady")
        val pre = clearPrecheck(g2, current == null, owner, current, keyOnlyNow, flagsRead.identityClearedStrict(), vaultNoKey, legacy)
        if (pre == ClearPrecheck.INCOMPLETE) {
            answer = IdentityClearCode.CLEAR_INCOMPLETE
        } else if (pre == ClearPrecheck.REFUSED_KEY_ONLY) {
            answer = IdentityClearCode.UNREGISTER_REFUSED
            reason = ClearFlagFiles.REASON_KEY_ONLY
        } else {
            val clearer = IdentityClear(
                flags = ClearFlagFiles(files),
                backupConfirmed = { true },
                migrationCheck = { counter.migrationChecks++; true },
                holdsWallet = { current != null },
                eraseWallet = { counter.erased++; true },
                eraseInbox = { counter.erased++; true },
                reportLegacyAbsent = { counter.erased++; true },
                clearPointer = { counter.erased++; true },
                currentEoa = current,
            )
            answer = when (clearGateStep(g2, current == null, owner, current)) {
                ClearGateStep.INCOMPLETE -> IdentityClearCode.CLEAR_INCOMPLETE
                ClearGateStep.RESUME -> clearer.clear()
                ClearGateStep.GATE -> if (g2) clearer.clear() else NoKeyGate.answerFor("clearIdentity", NoKeyGate.Gate.G0)
            }
        }
        if (expect.has("answerAnyOf")) {
            // The allowed set : the actual answer, with its reason, must be one of the listed pairs; answerNotIn must not contain it.
            val any = expect.getJSONArray("answerAnyOf")
            val ok = (0 until any.length()).any { i ->
                val o = any.getJSONObject(i)
                o.getString("answer") == answer && (!o.has("reason") || o.getString("reason") == reason) &&
                    (!o.has("reasonAllowed") || (0 until o.getJSONArray("reasonAllowed").length()).any { j ->
                        val r = o.getJSONArray("reasonAllowed").getString(j)
                        (r == "absent" && reason == null) || r == reason
                    })
            }
            if (!ok) out += "answer $answer/$reason is not in the allowed set"
            val reasonNotIn = expect.optJSONArray("reasonNotIn")
            if (reasonNotIn != null && reason != null && (0 until reasonNotIn.length()).any { reasonNotIn.getString(it) == reason }) out += "reason $reason is forbidden"
            val notIn = expect.optJSONArray("answerNotIn")
            if (notIn != null && (0 until notIn.length()).any { notIn.getString(it) == answer }) out += "answer $answer is forbidden"
        } else {
            check(out, "answer", expect.getString("answer"), answer)
            if (expect.has("reason")) check(out, "reason", expect.getString("reason"), reason)
        }
        val deleted = if (counter.erased > 0) listOf("X.remaining") else emptyList()
        check(out, "deleted", (0 until expect.getJSONArray("deleted").length()).map { expect.getJSONArray("deleted").getString(it) }, deleted)
        val wrote = files.map.toMap() != before || counter.erased > 0
        check(out, "writes", expect.getBoolean("writes"), wrote)
        if (expect.getString("marker") == "unknown") {
            // The marker could not be read: it must not be rewritten or removed (the bytes of the device are unchanged).
            if (files.map.toMap() != before) out += "marker or files changed"
        } else {
            check(out, "marker", if (expect.getString("marker") == "cleared") "absent" else expect.getString("marker"), markerWord(files))
        }
        return out
    }

    private fun runCold(c: JSONObject): List<String> {
        val out = mutableListOf<String>()
        val state = c.getJSONObject("state")
        val expect = c.getJSONObject("expect")
        val kind = state.getJSONObject("marker").getString("kind")
        val others = state.getBoolean("otherAccountEntries")
        val failure = state.getString("readFailure")
        // Every representation of another account's entry that the automatic finish can meet must block it; each is run on its own.
        val variants: List<String> = if (others) listOf("pgpOfZ", "setOfZ", "pointerAtZ", "pageCopyOfZ") else listOf("none")
        for (variant in variants) {
            val files = markerFiles(state)
            val before = files.map.toMap()
            val counter = Counter()
            val xScope = kind == "owned" && !others
            val pgp = when {
                variant == "pgpOfZ" -> listOf("pgp.v1.${bare(z)}.rec")
                xScope -> listOf("pgp.v1.${bare(x)}.rec", "pgp.v1.${bare(x)}.ok")
                else -> emptyList()
            }
            val set = if (variant == "setOfZ") MnemonicSetStore.Current.Found(z, MnemonicSetStore.Kind.PLAIN, "synthetic") else MnemonicSetStore.Current.Absent
            val pointer = when {
                variant == "pointerAtZ" -> PointerRead.At(z)
                xScope -> PointerRead.At(x)
                else -> PointerRead.None
            }
            val reads = RedoScopeReads(
                pgpNames = { if (failure == "otherAccountProbe") throw IOException("probe fault") else pgp },
                setCurrent = { set },
                pointer = { pointer },
                chatReadable = { if (failure == "chatEnumeration") throw IOException("chat fault") },
            )
            val holds: Boolean? = when {
                failure == "walletEnumeration" -> null
                variant == "pageCopyOfZ" -> true
                else -> false
            }
            val clearer = IdentityClear(
                flags = ClearFlagFiles(files),
                holdsWallet = { holds },
                eraseWallet = { counter.erased++; true },
                eraseInbox = { counter.erased++; true },
                reportLegacyAbsent = { counter.erased++; true },
                clearPointer = { counter.erased++; true },
                redoSafe = { owner -> redoScopeSafeReading(owner, reads) },
            )
            val code = clearer.redoIfInterrupted()
            val outcome = if (code == IdentityClearCode.OK) "finished" else "untouched"
            val tag = if (variants.size > 1) "[$variant] " else ""
            check(out, "${tag}outcome", expect.getString("outcome"), outcome)
            val deleted = if (counter.erased > 0) listOf("X.remaining") else emptyList()
            check(out, "${tag}deleted", (0 until expect.getJSONArray("deleted").length()).map { expect.getJSONArray("deleted").getString(it) }, deleted)
            val wrote = files.map.toMap() != before || counter.erased > 0
            check(out, "${tag}writes", expect.getBoolean("writes"), wrote)
            check(out, "${tag}marker", if (expect.getString("marker") == "cleared") "absent" else expect.getString("marker"), markerWord(files))
        }
        return out
    }
}
