package network.conet.chat.nativekey

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * (c) A new wallet's chat key does not occupy or overwrite the legacy armor location (2026-11-20). The legacy armor lives in the secure
 * store `beamio_chat_pgp_v1`; the native PGP vault lives in `native_wallet_v1`. Source guards: no main-source writer of the legacy store.
 * (d) After a restore with the original EOA, the armor is adopted by the normal adoption (behaviour of the pure adoption-EOA rule).
 * The device run of the restore is a known limitation (needs the mnemonic import flow).
 */
class ChatKeyAndRestoreAdoptionTest {
    private fun main(path: String): String = File("src/main/java/network/conet/chat/$path").readText(Charsets.UTF_8)

    @Test
    fun theLegacyPrivateArmorIsNeverWrittenInTheMainSources() {
        // Corrected 2026-11-20: the legacy store is written by upsertFromWeb (its EOA, public key, key id, route, entries),
        // so "no writer" was wrong. The claim is narrower: the private armor field is never put; the only removal is the explicit clear.
        val sources = File("src/main/java/network/conet/chat").walkTopDown().filter { it.name.endsWith(".kt") }.toList()
        val puts = sources.flatMap { file ->
            file.readLines(Charsets.UTF_8).filter { line ->
                (line.contains("putString(KEY_PRIVATE") || line.contains(".put(KEY_PRIVATE") || line.contains("putString(\"userPgpPrivateArmor\"")) &&
                    !line.trim().startsWith("//")
            }.map { file.name }
        }
        assertTrue("the private armor field is never written in the main sources", puts.isEmpty())
        val removals = File("src/main/java/network/conet/chat/BeamioChatPgpStore.kt").readLines(Charsets.UTF_8)
            .withIndex().filter { (_, line) -> line.contains("remove(KEY_PRIVATE)") }.map { it.index }
        assertEquals("C1: no removal of the armor anywhere in the store", 0, removals.size)
        assertFalse("clearLegacyPrivateArmor is removed", File("src/main/java/network/conet/chat/BeamioChatPgpStore.kt").readText(Charsets.UTF_8).contains("fun clearLegacyPrivateArmor("))
    }

    /**
     * Option A (2026-11-20): a web upsert with a legacy armor present writes its EOA to KEY_EOA_WEB, not to the owner KEY_EOA.
     * The adoption still compares KEY_EOA, so a mismatch settles as nothing only for a genuinely different owner. Behaviour in ArmorOwnerProtectionTest.
     */
    @Test
    fun aWebEoaWithAnArmorGoesToTheSeparateKey() {
        val store = File("src/main/java/network/conet/chat/BeamioChatPgpStore.kt").readText(Charsets.UTF_8)
        assertTrue("the web EOA goes to KEY_EOA_WEB while an armor exists", store.contains("editor.putString(KEY_EOA_WEB, secrets.eoa)"))
        val wallet = File("src/main/java/network/conet/chat/nativekey/AndroidNativeWallet.kt").readText(Charsets.UTF_8)
        assertTrue("the stopped adoption settles as nothing for any owner (2026-11-22)", wallet.contains("2026-11-22: the native PGP vault is an unpublished format"))
    }

    @Test
    fun theStoredOwnerIsCompareInLowerCase() {
        assertEquals("0xabc", readLegacyOwnerEoa { "0xABC " })
        assertEquals("", readLegacyOwnerEoa { null })
        assertNull(readLegacyOwnerEoa { throw java.io.IOException("unreadable") })
    }

    @Test
    fun theNativePgpVaultIsAnotherLocation() {
        val wallet = main("nativekey/AndroidNativeWallet.kt")
        assertTrue("the native PGP directory is native_wallet_v1, not the legacy store name", wallet.contains("DIR = \"native_wallet_v1\""))
        assertFalse("the native vault does not use the legacy store name", wallet.contains("beamio_chat_pgp_v1"))
    }

    @Test
    fun aRestoreWithTheOriginalEoaAdoptsTheArmor() {
        // The wallet is Ready with the EOA that the armor belongs to, and the native PGP record is empty: the EOA is the adoption target.
        assertEquals("0xabc", legacyAdoptionEoa(readWalletEoa = { "0xabc" }, readPgpIsNoKey = { true }))
    }

    @Test
    fun aWalletThatCannotBeReadIsUnknownNotAnEoa() {
        assertNull("no wallet EOA (unknown or absent) gives no adoption target", legacyAdoptionEoa(readWalletEoa = { null }, readPgpIsNoKey = { true }))
    }
}
