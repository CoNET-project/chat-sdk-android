package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.IOException
import network.conet.chat.ConetChatCryptoUtil
import org.json.JSONObject

/**
 * Consistency of the three answers (walletStatus, phraseVerdict, pre-read) on two paths the owner named (2026-11-17):
 *  (a) a fresh-account write that failed: the walletStatus is no_key, while the pre-read answers the valid phrase held under MNEM.isolated.*
 *      (the third position of the source order). That is the documented answer, not a contradiction.
 *  (c) a real read fault: the state read throws, and the answers are unknown (data kept, retryable), never no_key and never a throw to the page.
 */
class ConsistencyPathsTest {
    private val phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val wrap = NativeTestWrap()
    private fun key() = checkNotNull(MnemonicDerivation.deriveKey(phrase))
    private fun eoa() = checkNotNull(WalletAddress.fromPrivateKey(key()))

    private fun walletStatusOf(state: NativeWalletVault.State): String =
        NoKeyGate.walletStatusFor(NoKeyGate.gateOf(state, sessionReady = false), state).getString("status")

    /**
     * (a) A new account's write: the phrase and the records were written, the write failed, and the rollback moved every written record to an
     * isolated name (audit rows written). The fixed names are empty. walletStatus answers no_key; the pre-read answers the valid phrase from the copy.
     */
    @Test fun aFailedFreshWriteAnswersNoKeyWhileThePrereadAnswersTheIsolatedPhrase() {
        val files = NativeTestFiles()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eoa(), key(), phrase))
        assertTrue(NativeWalletVault(wrap, files).isolateWrittenRecords(mnemonicPlanned = true))
        NativeWalletVault.resetLaunchForTests()
        val v = NativeWalletVault(wrap, files)
        assertTrue("the fixed mnemonic name is empty", !files.map.containsKey(NativeWalletVault.MNEM))
        assertEquals("walletStatus answers no_key", "no_key", walletStatusOf(v.state()))
        val answer = MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(wrap, files))
        assertTrue("the pre-read answers the isolated valid phrase: $answer", answer is MnemonicPreread.Answer.Valid)
        assertEquals(phrase, (answer as MnemonicPreread.Answer.Valid).phrase)
    }

    /**
     * (c) A read fault on the phrase position (MNEM): the state read throws (it is not an absence), and the pre-read is unknown too (the fixed
     * phrase is not read, and it is not a listed marker entry). The snapshot is not set, so the module answers the storage unknown
     * (walletStatus not_ready, unreadable). Nothing is removed.
     */
    @Test fun aReadFaultOnThePhrasePositionIsUnknownForWalletStatusAndPreread() {
        val files = NativeTestFiles()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eoa(), key(), phrase))
        val before = files.map.keys.toSet()
        files.failRead = { it == NativeWalletVault.MNEM }
        NativeWalletVault.resetLaunchForTests()
        assertThrows(IOException::class.java) { NativeWalletVault(wrap, files).state() }
        val answer = MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(wrap, files))
        assertEquals("pre-read is unknown", MnemonicPreread.Answer.Unknown, answer)
        // The module answers the storage unknown when no snapshot is held (VaultSnapshotRefresh keeps it null after a failed refresh).
        assertTrue("walletStatus with no state is the storage unknown", NoKeyGate.storageAnswer("walletStatus", null) != null)
        assertEquals("not_ready", NoKeyGate.walletStatusUnreadable().getString("status"))
        files.failRead = null
        assertEquals("nothing removed by the fault", before, files.map.keys.toSet())
    }
}

/**
 *  (E9.1-3, E71-06-b): a read failure of REC or MARK does not decide the account. With the phrase at the fixed position valid,
 * the state, walletStatus, phraseVerdict, pre-read and the unlock key agree on that account. A failure of MNEM itself stays unknown.
 */
class RecMarkReadFaultTest {
    private val phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val wrap = NativeTestWrap()
    private fun key() = checkNotNull(MnemonicDerivation.deriveKey(phrase))
    private fun eoa() = checkNotNull(WalletAddress.fromPrivateKey(key()))

    private fun walletStatusOf(v: NativeWalletVault): String {
        val st = v.state()
        return NoKeyGate.walletStatusFor(NoKeyGate.gateOf(st, sessionReady = false), st).getString("status")
    }

    private fun assertAgreeingAccount(files: NativeTestFiles) {
        val control = NativeTestFiles()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, control).importMnemonicKey(eoa(), key(), phrase))
        val controlStatus = walletStatusOf(NativeWalletVault(wrap, control))
        NativeWalletVault.resetLaunchForTests()
        val v = NativeWalletVault(wrap, files)
        val st = v.state()
        assertTrue("the state is a ready account: $st", st is NativeWalletVault.State.Ready)
        assertEquals(eoa(), (st as NativeWalletVault.State.Ready).eoa)
        assertEquals("phrase verdict is valid", NativeWalletVault.PhraseVerdict.VALID, v.phraseVerdict())
        assertEquals("walletStatus equals the no-fault account", controlStatus, walletStatusOf(v))
        val answer = MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(wrap, files))
        assertTrue("pre-read valid: $answer", answer is MnemonicPreread.Answer.Valid)
        assertEquals(phrase, (answer as MnemonicPreread.Answer.Valid).phrase)
        assertTrue("the unlock key is the phrase's key", NativeWalletVault(wrap, files).unlock()?.contentEquals(key()) == true)
    }

    @Test fun aRecReadFaultWithAValidPhraseIsAReadyAccountAgreeing() {
        val files = NativeTestFiles()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eoa(), key(), phrase))
        files.failRead = { it == NativeWalletVault.REC }
        assertAgreeingAccount(files)
    }

    @Test fun aMarkReadFaultWithAValidPhraseIsAReadyAccountAgreeing() {
        val files = NativeTestFiles()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eoa(), key(), phrase))
        files.failRead = { it == NativeWalletVault.MARK }
        assertAgreeingAccount(files)
    }

    /** A failure of the phrase position itself is unknown, whatever REC holds (E7.1-2). */
    @Test fun aMnemReadFaultStaysUnknown() {
        val files = NativeTestFiles()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eoa(), key(), phrase))
        files.failRead = { it == NativeWalletVault.MNEM }
        NativeWalletVault.resetLaunchForTests()
        assertThrows(IOException::class.java) { NativeWalletVault(wrap, files).state() }
        assertThrows(IOException::class.java) { NativeWalletVault(wrap, files).phraseVerdict() }
        assertEquals(MnemonicPreread.Answer.Unknown, MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(wrap, files)))
    }
}

/**
 * REC/MARK fault with the phrase position read cleanly and empty: the record is no account; state, walletStatus and the
 * pre-read agree (no_key / absent). The REC and MARK bytes are kept. A valid isolated copy is the third source position (pre-read valid).
 */
class RecMarkFaultWithNoPhraseTest {
    private val phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val wrap = NativeTestWrap()
    private fun key() = checkNotNull(MnemonicDerivation.deriveKey(phrase))
    private fun eoa() = checkNotNull(WalletAddress.fromPrivateKey(key()))

    private fun base(): NativeTestFiles {
        val files = NativeTestFiles()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eoa(), key(), phrase))
        files.map.remove(NativeWalletVault.MNEM)
        return files
    }

    private fun assertNoAccount(files: NativeTestFiles, fault: String) {
        NativeWalletVault.resetLaunchForTests()
        val v = NativeWalletVault(wrap, files)
        assertEquals("$fault: state is no account", NativeWalletVault.State.NoKey, v.state())
        val st = v.state()
        assertEquals("$fault: walletStatus is no_key", "no_key",
            NoKeyGate.walletStatusFor(NoKeyGate.walletStatusGate(st, sessionReady = true, keyOnly = v.isKeyOnlyAccount()), st).getString("status"))
        assertEquals("$fault: pre-read is absent", MnemonicPreread.Answer.Absent, MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(wrap, files)))
        assertTrue("$fault: the record bytes are kept", files.map.containsKey(NativeWalletVault.REC) || fault == "MARK")
    }

    @Test fun recFaultWithAnEmptyPhrasePositionIsNoAccountAgreeing() {
        val files = base()
        files.failRead = { it == NativeWalletVault.REC }
        val rec = files.map.getValue(NativeWalletVault.REC).copyOf()
        assertNoAccount(files, "REC")
        files.failRead = null
        assertTrue("REC bytes unchanged", rec.contentEquals(files.map.getValue(NativeWalletVault.REC)))
    }

    @Test fun markFaultWithAnEmptyPhrasePositionIsNoAccountAgreeing() {
        val files = base()
        files.failRead = { it == NativeWalletVault.MARK }
        assertNoAccount(files, "MARK")
    }

    @Test fun recFaultWithAValidIsolatedCopyPrereadIsValidOnTheThirdPosition() {
        val files = base()
        files.map["${NativeWalletVault.MNEM}.isolated.20261117T000000Z.abcdef02"] = files.map.getValue(NativeWalletVault.REC).copyOf().let {
            // a sealed phrase copy under the same envelope as the fixed mnemonic file
            JSONObject().put("record", NativeWalletVault.RECORD_VERSION).put("eoa", eoa())
                .put("sealed", ConetChatCryptoUtil.toHex(wrap.seal(NativeWalletVault.mnemAad(eoa()), phrase.toByteArray(Charsets.UTF_8))))
                .toString().toByteArray(Charsets.UTF_8)
        }
        files.failRead = { it == NativeWalletVault.REC }
        NativeWalletVault.resetLaunchForTests()
        val answer = MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(wrap, files))
        assertTrue("pre-read valid on the third position: $answer", answer is MnemonicPreread.Answer.Valid)
        assertEquals(NativeWalletVault.State.NoKey, NativeWalletVault(wrap, files).state())
    }
}

/**
 * a phrase record with a clear EOA that cannot be decrypted is a read failure: state, walletStatus and the pre-read are
 * unknown (never no_key, never ready), and no byte is deleted. A confirmed wrap loss keeps its own answer (SO-22A, WK vectors).
 */
class MnemDecryptFailureTest {
    private val phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val wrap = NativeTestWrap()
    private fun key() = checkNotNull(MnemonicDerivation.deriveKey(phrase))
    private fun eoa() = checkNotNull(WalletAddress.fromPrivateKey(key()))

    @Test fun aPhraseRecordThatDoesNotDecryptIsUnknownEverywhereAndKeepsEveryByte() {
        val files = NativeTestFiles()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eoa(), key(), phrase))
        // Corrupt the sealed bytes of the fixed phrase record (the clear EOA stays): the AEAD open fails.
        val o = JSONObject(String(files.map.getValue(NativeWalletVault.MNEM), Charsets.UTF_8))
        val sealed = o.getString("sealed")
        o.put("sealed", (if (sealed.startsWith("0")) "1" else "0") + sealed.substring(1))
        files.map[NativeWalletVault.MNEM] = o.toString().toByteArray(Charsets.UTF_8)
        val before = files.map.mapValues { it.value.copyOf() }
        NativeWalletVault.resetLaunchForTests()
        val v = NativeWalletVault(wrap, files)
        val st = v.state()
        assertTrue("state is unknown (locked), not ready or no key: $st", st is NativeWalletVault.State.Locked)
        val status = NoKeyGate.walletStatusFor(NoKeyGate.walletStatusGate(st, sessionReady = true, keyOnly = false), st).getString("status")
        assertTrue("walletStatus is not no_key or unlocked: $status", status != "no_key" && status != "unlocked")
        assertEquals("phrase verdict is unknown", NativeWalletVault.PhraseVerdict.UNKNOWN, v.phraseVerdict())
        assertEquals("pre-read is unknown", MnemonicPreread.Answer.Unknown, MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(wrap, files)))
        assertEquals("no byte is deleted or changed", before.keys, files.map.keys)
        for ((k, b) in before) assertTrue("bytes kept: $k", files.map.getValue(k).contentEquals(b))
    }
}
