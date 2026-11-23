package network.conet.chat.nativekey

import network.conet.chat.nativekey.MnemonicPreread.Answer
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.IOException

/**
 * The pre-read under the decision of 2026-11-17 ("a half-written window is ignorable; with no mnemonic the answer is onboarding"): a pending marker,
 * an intent or an old marker never by themselves make the answer unknown; a valid phrase in the vault (fixed or in a sealed copy) is valid; a read
 * that fails is unknown. The pre-read removes nothing.
 */
class PrereadHalfWriteTest {
    private val phraseA = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val phraseB = "legal winner thank year wave sausage worth useful legal winner thank yellow"
    private val wrap = NativeTestWrap()

    @Before fun newLaunch() {
        NativeWalletVault.resetLaunchForTests()
        MnemonicPreread.resetForTests()
    }

    private fun keyOf(p: String) = checkNotNull(MnemonicDerivation.deriveKey(p))
    private fun eoaOf(p: String) = checkNotNull(WalletAddress.fromPrivateKey(keyOf(p)))

    /** The window: account A (keyOnly or with its phrase), then the write of B stopped right after REC. */
    private fun window(withPhraseA: Boolean, schema1: Boolean = false): NativeTestFiles {
        val files = NativeTestFiles()
        val kA = keyOf(phraseA)
        if (withPhraseA) {
            NativeWalletVault(wrap, files).importMnemonicKey(eoaOf(phraseA), kA, phraseA)
        } else {
            NativeWalletVault(wrap, files).importKey(eoaOf(phraseA), kA)
            files.map.remove(NativeWalletVault.MNEM)
        }
        files.crashAfterWrite = NativeWalletVault.REC
        try {
            NativeWalletVault(wrap, files).syncPhrase(eoaOf(phraseB), keyOf(phraseB), phraseB)
        } catch (_: NativeTestCrash) {
        }
        files.crashAfterWrite = null
        if (schema1) {
            val o = JSONObject(String(files.map.getValue(NativeWalletVault.PENDING), Charsets.UTF_8))
            listOf("startCredential", "startEoa", "startRecordedUtc", "startSchemaVersion").forEach { o.remove(it) }
            files.map[NativeWalletVault.PENDING] = o.toString().toByteArray(Charsets.UTF_8)
        }
        return files
    }

    private fun answer(files: NativeTestFiles): Answer = MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(wrap, files))

    /** Both sides empty (no phrase anywhere) and a half-written window: absent. */
    @Test fun bothSidesEmptyWithAHalfWriteIsAbsent() {
        val files = window(withPhraseA = false)
        assertTrue("the window is on disk", files.map.containsKey(NativeWalletVault.PENDING))
        assertEquals(Answer.Absent, answer(files))
    }

    /** An old (schema-1) marker, no phrase: absent. */
    @Test fun anOldMarkerWithNoPhraseIsAbsent() {
        val files = window(withPhraseA = false, schema1 = true)
        assertEquals(Answer.Absent, answer(files))
    }

    /**
     * A sealed copy of the old account holds its valid phrase, but the window is an unsettled OVERWRITE (its marker has overwrite=true and lists the
     * isolated REC/MNEM copy). Field overwrite (iii): unknown until a write settles it. Changed from valid on 2026-11-18; the
     * four 2026-11-17 expectations of this kind are agreed by the project on 2026-11-18.
     */
    @Test fun aSealedCopyWithAValidPhraseIsUnknownWhileAnOverwriteIsUnsettled() {
        val files = window(withPhraseA = true)
        val a = answer(files)
        assertTrue("unknown: $a", a is Answer.Unknown)
    }

    /** A read that fails at a phrase or record name is unknown (never absent). */
    @Test fun aReadFailureIsUnknown() {
        // No pending marker: the phrase item is an ordinary entry, so its read failure is unknown.
        val files = NativeTestFiles()
        NativeWalletVault(wrap, files).importMnemonicKey(eoaOf(phraseA), keyOf(phraseA), phraseA)
        val failing = object : VaultFiles by files {
            override fun read(name: String): ByteArray? {
                if (name == NativeWalletVault.MNEM) throw IOException("read failed")
                return files.read(name)
            }
        }
        assertEquals(Answer.Unknown, MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(wrap, failing)))
    }

    /** A sealed copy that does not open (garbage) is unreadable: unknown. */
    @Test fun anUnopenableSealedCopyIsUnknown() {
        val files = window(withPhraseA = false)
        files.map["${NativeWalletVault.MNEM}.isolated.20261117T000000Z.deadbeef"] = "garbage".toByteArray()
        assertEquals(Answer.Unknown, answer(files))
    }

    /** Two different valid accounts among the copies: unknown (the multi-account rule is not decided here). */
    @Test fun twoValidAccountsAreUnknown() {
        val files = window(withPhraseA = true)
        val other = NativeTestFiles()
        NativeWalletVault(wrap, other).importMnemonicKey(eoaOf(phraseB), keyOf(phraseB), phraseB)
        files.map["${NativeWalletVault.MNEM}.isolated.20261117T000000Z.cafef00d"] = other.map[NativeWalletVault.MNEM]!!.copyOf()
        assertEquals(Answer.Unknown, answer(files))
    }

    /** The pre-read changes nothing: every byte string and the marker stay as they were. */
    @Test fun thePreReadRemovesNothing() {
        val files = window(withPhraseA = true)
        val before = files.map.mapValues { it.value.copyOf() }
        answer(files)
        assertEquals(before.keys, files.map.keys)
        before.forEach { (n, b) -> assertTrue("$n unchanged", b.contentEquals(files.map[n])) }
    }

    /** E9.1-1: the phrase entry the pending marker lists as an unfinished write is read best-effort: its read failure is ignored, and the sealed copy decides. */
    /** A wrap whose key is present (so an authentication failure is deterministic). */
    private val presentWrap: KeyWrap = object : KeyWrap by wrap {
        override fun presence(): WrapKeyPresence = WrapKeyPresence.PRESENT
    }

    /**  (transient vs deterministic): a listed entry that is corrupt (deterministic, authentication fails with the key present) is ignored; the copy decides. */
    @Test fun aListedEntryReadFailureIsIgnoredAndTheCopyDecides() {
        val files = window(withPhraseA = true)
        assertTrue("the marker lists the mnemonic entry", String(files.map.getValue(NativeWalletVault.PENDING), Charsets.UTF_8).contains("\"name\":\"${NativeWalletVault.MNEM}\""))
        // The listed fixed entry is present and corrupt (its sealed bytes do not authenticate under the present key).
        val corrupt = JSONObject().put("record", 1).put("eoa", eoaOf(phraseA)).put("sealed", "00".repeat(40)).toString().toByteArray(Charsets.UTF_8)
        val failing = object : VaultFiles by files {
            override fun read(name: String): ByteArray? = if (name == NativeWalletVault.MNEM) corrupt else files.read(name)
        }
        // Changed 2026-11-18 (iii, field overwrite): the window is an unsettled overwrite, so the valid copy is not answered valid.
        val a = MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(presentWrap, failing))
        assertTrue("unknown while the overwrite is unsettled: $a", a is Answer.Unknown)
    }

    /** X1: a listed mnemonic entry whose read throws is transient: unknown, never Absent (onboarding). */
    @Test fun x1AListedMnemonicReadThatThrowsIsUnknownNotAbsent() {
        val files = window(withPhraseA = false)
        val failing = object : VaultFiles by files {
            override fun read(name: String): ByteArray? {
                if (name == NativeWalletVault.MNEM) throw IOException("storage read failed")
                return files.read(name)
            }
        }
        assertEquals(Answer.Unknown::class, MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(wrap, failing))::class)
    }

    /** X3: the wrap key is not confirmed present (absent or unknown) while the record exists: transient, unknown, never Absent. */
    @Test fun x3AKeyNotConfirmedPresentWithARecordIsUnknownNotAbsent() {
        val files = window(withPhraseA = true)
        val notPresent: KeyWrap = object : KeyWrap by wrap {
            override fun open(aad: ByteArray, sealed: ByteArray): ByteArray? = null
            override fun presence(): WrapKeyPresence = WrapKeyPresence.UNKNOWN
        }
        assertEquals(Answer.Unknown::class, MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(notPresent, files))::class)
    }

    /** E9.1-1 (copies): a sealed copy the pending marker lists is read best-effort: its read failure is ignored; another position decides. */
    @Test fun aListedSealedCopyReadFailureIsIgnoredAndAnotherPositionDecides() {
        // Deterministic: the listed copy is corrupt (authentication fails with the key present); the other position decides.
        val files = window(withPhraseA = true)
        val listed = files.map.keys.single { it.startsWith("${NativeWalletVault.MNEM}.isolated.") }
        assertTrue("the marker lists the sealed copy", String(files.map.getValue(NativeWalletVault.PENDING), Charsets.UTF_8).contains("\"isolated\":\"$listed\""))
        // A second, unlisted sealed copy holds the valid phrase of the same account (another position).
        val other = "${NativeWalletVault.MNEM}.isolated.20261117T000000Z.feedface"
        files.map[other] = files.map[listed]!!.copyOf()
        val corrupt = files.map.getValue(listed).copyOf().also { it[it.size - 6] = (it[it.size - 6].toInt() xor 1).toByte() }
        val failing = object : VaultFiles by files {
            override fun read(name: String): ByteArray? = if (name == listed) corrupt else files.read(name)
        }
        // Changed 2026-11-18 (iii, field overwrite): the window is an unsettled overwrite, so the other position is not answered valid.
        val a = MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(presentWrap, failing))
        assertTrue("unknown while the overwrite is unsettled: $a", a is Answer.Unknown)
    }
}
