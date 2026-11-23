package network.conet.chat.nativekey

import network.conet.chat.BeamioConetChatProtocol
import network.conet.chat.BuildConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Capability identity.kpresent.v1 (spec 25.52X.5, 25.52Y.93). Declared again (rc2.2-qa, coordinator order after): the import page now
 * carries `eoa` on `already_exists` (`nativeImportResult`, 25.52X.4), so the recovery and import paths both carry it.
 */
class KPresentCapabilityTest {
    @Test
    fun helloDeclaresIdentityKPresentV1InEveryBuild() {
        assertEquals("identity.kpresent.v1", BeamioConetChatProtocol.KPRESENT_CAPABILITY)
        assertTrue("declared in CAPABILITIES", BeamioConetChatProtocol.CAPABILITIES.contains("identity.kpresent.v1"))
        val caps = BeamioConetChatProtocol.helloResult().getJSONArray("capabilities")
        val names = (0 until caps.length()).map { caps.getString(it) }
        assertTrue("hello answer carries identity.kpresent.v1", names.contains("identity.kpresent.v1"))
    }

    @Test
    fun theProductionNamesAreUnchangedAndKPresentFollowsThem() {
        // The kPresent name is added after the production names; the QA-only names keep their own gating.
        val base = listOf(
            "identity.provision", "signing.local", "lifecycle.daemon", "inbound.deferAck", "history.v2", "call.control", "voice.delegated",
            "presence.query", "mailbox.command", "send.mailboxWrap", "history.local.v1", "history.page.v1", "layout.cache.v1",
        )
        assertEquals(base + "identity.kpresent.v1", BeamioConetChatProtocol.CAPABILITIES.take(base.size + 1))
    }

    /**
     * Formal hello (2026-11-16): identity.native-keys.v1 is declared by every build, directly after kPresent. The formal
     * configuration carries no QA name: wallet.credential.v1 is absent unless the wallet-credential QA switch is set (QA-only).
     */
    @Test
    fun theFormalHelloDeclaresNativeKeysAndNoQaName() {
        val names = BeamioConetChatProtocol.CAPABILITIES
        assertTrue(names.contains("identity.native-keys.v1"))
        assertEquals("identity.native-keys.v1", names[names.indexOf("identity.kpresent.v1") + 1])
        assertEquals(BuildConfig.WALLET_CREDENTIAL_QA, names.contains("wallet.credential.v1"))
        assertTrue("the formal build has no wallet-credential QA switch", !BuildConfig.WALLET_CREDENTIAL_QA)
        val hello = BeamioConetChatProtocol.helloResult().getJSONArray("capabilities")
        for (i in 0 until hello.length()) {
            assertTrue("no QA name in hello: ${hello.getString(i)}", !hello.getString(i).lowercase().contains("qa"))
        }
    }
}
