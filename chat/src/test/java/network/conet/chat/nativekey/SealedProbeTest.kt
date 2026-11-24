package network.conet.chat.nativekey

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.security.SecureRandom

/**
 * The sealed-record probe of the wrap seal after a device finding: a store account's device has no wrap alias and a plaintext
 * migration marker in the vault directory, and the marker was counted as a sealed record, so no key could ever be created (vault_write_failed).
 * The exclusion is a fixed list (the exact `.last` marker with the exact JSON), never a wildcard; everything else still counts as sealed, so a lost alias
 * with any real, unknown or damaged record still fails closed.
 */
class SealedProbeTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private val eoa = "0x" + "ab".repeat(20)
    private val bare = "ab".repeat(20)
    private val lastName = "pgp.v1.mig.$bare.default.last"
    private val validLast = """{"v":1,"code":"verify_unavailable"}"""

    private fun dir(vararg files: Pair<String, String>): File = tmp.newFolder().also { d -> files.forEach { (n, c) -> File(d, n).writeText(c) } }

    /** The seal decision with the real probe over [d] and an alias that is absent; true when a key may be created. */
    private fun mayCreate(d: File): Boolean {
        var created = false
        try {
            resolveSealKey(
                presence = { WrapKeyPresence.CONFIRMED_ABSENT },
                sealedRecordsExist = { sealedRecordsIn(d) },
                existing = { null as Any? },
                create = { created = true; Any() },
            )
        } catch (_: WrapKeyMissingException) {
            return false
        }
        return created
    }

    @Test
    fun onlyTheExactPlainMarkerLetsTheFirstKeyBeCreated() {
        assertTrue("an empty directory", mayCreate(dir()))
        assertTrue("the plain marker alone", mayCreate(dir(lastName to validLast)))
        assertFalse("the plain marker is not a sealed record", sealedRecordsIn(dir(lastName to validLast)))
    }

    @Test
    fun aRealSealedRecordWithALostAliasStillFailsClosed() {
        for (name in listOf("wallet.v1.rec", "wallet.v1.ok", "wallet.v1.mnem", "pgp.v1.$bare.rec", "pgp.v1.$bare.ok", "pgp.v1.mig.$bare.default.n", "pgp.v1.mig.$bare.default.m")) {
            assertFalse("$name fails closed", mayCreate(dir(name to "x")))
            assertFalse("$name next to the plain marker fails closed", mayCreate(dir(name to "x", lastName to validLast)))
        }
    }

    @Test
    fun anUnknownFileStillFailsClosed() {
        assertFalse(mayCreate(dir("something.bin" to "x")))
        assertFalse(mayCreate(dir("pgp.v1.mig.$bare.default.other" to validLast)))
        assertFalse("a leftover temp of the marker", mayCreate(dir("$lastName.tmp" to validLast)))
    }

    @Test
    fun aMarkerNameOutsideTheListIsSealed() {
        for (name in listOf(
            "pgp.v1.mig.${"ab".repeat(19)}a.default.last", // 39 hex
            "pgp.v1.mig.${"AB".repeat(20)}.default.last", // upper case
            "pgp.v1.mig.$bare.other.last", // another workspace
            "pgp.v1.mig.$bare.default.last.bak",
            "x.pgp.v1.mig.$bare.default.last",
        )) {
            assertFalse("$name is sealed to the probe", mayCreate(dir(name to validLast)))
        }
    }

    @Test
    fun aDamagedMarkerCountsAsSealed() {
        val bad = listOf(
            "not json",
            "",
            """{"v":1}""",
            """{"code":"verify_unavailable"}""",
            """{"v":2,"code":"verify_unavailable"}""",
            """{"v":"1","code":"verify_unavailable"}""",
            """{"v":1,"code":"Verify Unavailable"}""",
            """{"v":1,"code":""}""",
            """{"v":1,"code":5}""",
            """{"v":1,"code":"ok","extra":"x"}""",
            """["v",1]""",
            """{"v":1,"code":"${"a".repeat(200)}"}""",
        )
        for (content in bad) assertFalse("damaged marker '${content.take(30)}' is sealed", mayCreate(dir(lastName to content)))
    }

    @Test
    fun theMarkerIsOnlyReadWhenItIsSmall() {
        assertFalse(mayCreate(dir(lastName to validLast + " ".repeat(300))))
    }

    @Test
    fun aMarkerThatIsADirectoryIsSealed() {
        val d = tmp.newFolder()
        File(d, lastName).mkdir()
        assertFalse(mayCreate(d))
    }

    @Test
    fun isolatedFilesAndTheAuditStillDoNotCount() {
        assertTrue(mayCreate(dir("wallet.v1.rec.isolated.1" to "x", NativeWalletVault.AUDIT to "x", NativeWalletVault.RETAINED to "x", NativeWalletVault.PENDING to "x")))
    }

    // ---- the vault write end to end: no alias, only the plain marker -----------------------------------------------------------------------

    private class AliasWrap(private val d: File) : KeyWrap {
        var alias: javax.crypto.SecretKey? = null
        private val inner = NativeTestWrap()
        override fun seal(aad: ByteArray, plain: ByteArray): ByteArray {
            resolveSealKey(
                presence = { if (alias != null) WrapKeyPresence.PRESENT else WrapKeyPresence.CONFIRMED_ABSENT },
                sealedRecordsExist = { sealedRecordsIn(d) },
                existing = { alias },
                create = { javax.crypto.KeyGenerator.getInstance("AES").generateKey().also { alias = it } },
            )
            return inner.seal(aad, plain)
        }
        override fun open(aad: ByteArray, sealed: ByteArray): ByteArray? = if (alias == null) null else inner.open(aad, sealed)
        override fun deleteKey(): Boolean = true
        override fun presence(): WrapKeyPresence = if (alias != null) WrapKeyPresence.PRESENT else WrapKeyPresence.CONFIRMED_ABSENT
    }

    private fun vaultOver(d: File, wrap: KeyWrap) = NativePgpVault(wrap, AndroidVaultFiles(d), eoa)

    @Test
    fun withOnlyThePlainMarkerAndNoAliasTheVaultPutCreatesTheAliasAndWrites() {
        val d = dir(lastName to validLast)
        val wrap = AliasWrap(d)
        val armor = RecKeys.generate(eoa, SecureRandom()).privateArmor
        assertEquals(NativePgpVault.Put.OK, vaultOver(d, wrap).put(eoa, armor, ""))
        assertNotNull("the alias was created", wrap.alias)
        assertTrue(vaultOver(d, wrap).state() is NativePgpVault.State.Ready)
        assertEquals("the marker is untouched", validLast, File(d, lastName).readText())
    }

    @Test
    fun withARealRecordAndNoAliasTheVaultPutFailsClosedAndWritesNothingNew() {
        val d = dir("wallet.v1.rec" to "sealed", lastName to validLast)
        val wrap = AliasWrap(d)
        val armor = RecKeys.generate(eoa, SecureRandom()).privateArmor
        assertEquals(NativePgpVault.Put.STORE_FAILED, vaultOver(d, wrap).put(eoa, armor, ""))
        assertEquals(null, wrap.alias)
        assertFalse(File(d, NativePgpVault.recName(eoa)).exists())
        assertEquals("sealed", File(d, "wallet.v1.rec").readText())
    }

    @Test
    fun theProbeAndThePutLogOnlyReasonsNeverNames() {
        val probe = File("src/main/java/network/conet/chat/nativekey/AndroidNativeWallet.kt").readText()
        assertTrue(probe.contains("DiagTiming.log(\"vault.sealedProbe\", DiagTiming.now(), \"sealed=\$sealed plainMarkers=\$plain\")"))
        val vault = File("src/main/java/network/conet/chat/nativekey/NativePgpVault.kt").readText()
        assertTrue(vault.contains("DiagTiming.log(\"vault.put:seal\", DiagTiming.now(), e.javaClass.simpleName)"))
        assertTrue(vault.contains("DiagTiming.log(\"vault.put:write\", DiagTiming.now(), e.javaClass.simpleName)"))
        val auto = File("src/main/java/network/conet/chat/nativekey/AutoRecovery.kt").readText()
        assertTrue(auto.contains("retry(\"vault_write_failed:\${put.code}\")"))
    }

    @Test
    fun theListHoldsExactlyOneKindAndNoWildcard() {
        val src = File("src/main/java/network/conet/chat/nativekey/AndroidNativeWallet.kt").readText()
        val body = src.substring(src.indexOf("internal object KnownPlainMarkers"))
        assertEquals("one regex for names", 1, Regex("""Regex\(""").findAll(body.substringBefore("fun nameMatches")).count() - 1)
        assertTrue(body.contains(".last\$"))
        if (body.contains(".*")) fail("no wildcard in the marker list")
    }
}
