package network.conet.chat.nativekey

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Alignment v2 (K-add, 2026-11-17; 33(5) kept as is, no rename and no isolation): a private-only record is never removed on the
 * explicit-empty path. K-01: the PWA's explicit empty with a native account that holds only a key: every byte is still there. K-02: the audit
 * line cannot be written: nothing is removed either, and the answer is NOT_DROPPED.
 * Hand-written from the K pre-state (the K vector file is not vendored with the tests).
 */
class KeepPrivateOnlyTest {
    private val phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    private fun keyOnly(): Pair<NativeTestFiles, NativeTestWrap> {
        val files = NativeTestFiles()
        val wrap = NativeTestWrap()
        val k = checkNotNull(MnemonicDerivation.deriveKey(phrase))
        val eoa = checkNotNull(WalletAddress.fromPrivateKey(k))
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importKey(eoa, k))
        return files to wrap
    }

    @Test fun k01_explicitEmptyWithOnlyAPrivateKeyKeepsEveryByte() {
        val (files, wrap) = keyOnly()
        val names = files.names()
        val before = names.associateWith { files.read(it)!! }
        val vault = NativeWalletVault(wrap, files)
        assertEquals(NativeWalletVault.DiscardOutcome.NOT_DROPPED, vault.discardPrivateOnly(pwaExplicitEmpty = true, nativeState = vault.nativeStateLabel()))
        assertEquals(names.toSet(), files.names().toSet())
        before.forEach { (n, b) -> assertArrayEquals(n, b, files.read(n)) }
    }

    @Test fun k02_anAuditWriteFailureDeletesNothing() {
        val (inner, wrap) = keyOnly()
        val names = inner.names()
        val before = names.associateWith { inner.read(it)!! }
        val files = object : VaultFiles by inner {
            override fun write(name: String, bytes: ByteArray) {
                if (name == NativeWalletVault.DISCARD_AUDIT || name == NativeWalletVault.AUDIT) throw java.io.IOException("audit write refused")
                inner.write(name, bytes)
            }
        }
        val vault = NativeWalletVault(wrap, files)
        assertEquals(NativeWalletVault.DiscardOutcome.NOT_DROPPED, vault.discardPrivateOnly(pwaExplicitEmpty = true, nativeState = vault.nativeStateLabel()))
        before.forEach { (n, b) -> assertArrayEquals(n, b, inner.read(n)) }
    }
}
