package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger

/**
 * 25.52Y.92 (coordinator, rc2.2-qa): the legacy pure-key exception. A readable key record with no phrase, no intent, no commit marker and no
 * digest is accepted as it is. An intent, a digest or a phrase without the commit marker is unreadable, never accepted or repaired.
 * In memory only; no device or real directory is touched.
 */
class LegacyKeyExceptionTest {
    private val eoa = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
    private val key = ByteArray(32).also { it[31] = 1 } // the scalar 1, the key of [eoa]
    private val phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val phraseEoa = "0x9858effd232b4033e47d90003d41ec34ecaeda94"

    /** A record written by the vault's own import: REC, the digest (MARK) and the commit marker (COMMIT). */
    private fun imported(): Pair<NativeTestFiles, NativeTestWrap> {
        val files = NativeTestFiles()
        val wrap = NativeTestWrap()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importKey(eoa, key))
        return files to wrap
    }

    /** Positive control: a pure legacy key (readable record, no phrase, intent, commit or digest) is accepted and nothing changes. */
    @Test
    fun pureLegacyKeyIsAcceptedAsItIs() {
        val (files, wrap) = imported()
        files.map.remove(NativeWalletVault.MARK)
        files.map.remove(NativeWalletVault.COMMIT)
        val before = files.map.mapValues { it.value.copyOf() }

        val s = NativeWalletVault(wrap, files).state()

        assertTrue("accepted as the account", s is NativeWalletVault.State.Ready)
        assertEquals(eoa, (s as NativeWalletVault.State.Ready).eoa)
        assertEquals("nothing is written or removed", before.keys, files.map.keys)
    }

    /** Coordinator: a commit marker with no digest is unreadable. It is not the legacy exception (the commit marker is present). */
    @Test
    fun commitMarkerWithoutDigestIsUnreadable() {
        val (files, wrap) = imported()
        files.map.remove(NativeWalletVault.MARK)
        val before = files.map.mapValues { it.value.copyOf() }

        val s = NativeWalletVault(wrap, files).state()

        assertTrue("not accepted", s is NativeWalletVault.State.Locked)
        assertEquals("marker_missing", (s as NativeWalletVault.State.Locked).reason)
        assertEquals("the record is kept", before.keys, files.map.keys)
        assertFalse("no digest is generated", files.map.containsKey(NativeWalletVault.MARK))
    }

    /** A digest with no commit marker (an interrupted write) is unreadable: not the legacy exception, not repaired. */
    @Test
    fun digestWithoutCommitMarkerIsUnreadable() {
        val (files, wrap) = imported()
        files.map.remove(NativeWalletVault.COMMIT)
        val before = files.map.mapValues { it.value.copyOf() }

        val s = NativeWalletVault(wrap, files).state()

        assertTrue("not accepted", s is NativeWalletVault.State.Locked)
        assertEquals("the names are unchanged", before.keys, files.map.keys)
        assertTrue("the digest is kept", files.map.containsKey(NativeWalletVault.MARK))
        assertFalse("no commit marker is generated", files.map.containsKey(NativeWalletVault.COMMIT))
    }

    /**
     * An intent present before the reconcile (25.52Y.92 第 3 項): the reconcile removes the intent, so the read must take it before. The record
     * is then unreadable, and it is not accepted as a pure-key record.
     */
    @Test
    fun intentPresentBeforeTheReconcileIsUnreadableNotLegacy() {
        val (files, wrap) = imported()
        files.map.remove(NativeWalletVault.MARK)
        files.map.remove(NativeWalletVault.COMMIT)
        val v = NativeWalletVault(wrap, files)
        files.map[NativeWalletVault.INTENT] = v.encodeIntent(eoa, mnemonicPlanned = false, created = emptyList())

        val s = NativeWalletVault(wrap, files).state()

        assertTrue("an intent present before the reconcile is not the legacy exception", s is NativeWalletVault.State.Locked)
        assertEquals("marker_missing", (s as NativeWalletVault.State.Locked).reason)
        assertTrue("the record is kept", files.map.containsKey(NativeWalletVault.REC))
        assertFalse("no digest is generated", files.map.containsKey(NativeWalletVault.MARK))
    }

    /** A phrase record with no digest is unreadable (the phrase rule, 25.52Y.42 第 4 項 (g)). */
    @Test
    fun phraseRecordWithoutDigestIsUnreadable() {
        val files = NativeTestFiles()
        val wrap = NativeTestWrap()
        val v = NativeWalletVault(wrap, files)
        assertEquals(NativeWalletVault.Import.OK, v.importMnemonicKey(phraseEoa, MnemonicDerivation.deriveKey(phrase)!!, phrase))
        files.map.remove(NativeWalletVault.MARK)

        val s = NativeWalletVault(wrap, files).state()

        assertTrue("not accepted", s is NativeWalletVault.State.Locked)
        assertEquals("marker_missing", (s as NativeWalletVault.State.Locked).reason)
    }

    /** The legacy exception is not for a record with a phrase: the phrase makes it a marker-rule record. */
    @Test
    fun legacyExceptionIsOnlyForAPureKey() {
        val (files, wrap) = imported()
        files.map.remove(NativeWalletVault.MARK)
        files.map.remove(NativeWalletVault.COMMIT)
        files.map[NativeWalletVault.MNEM] = byteArrayOf(9, 9, 9)

        val s = NativeWalletVault(wrap, files).state()

        assertFalse("a phrase record is never the legacy exception", s is NativeWalletVault.State.Ready)
    }
}
