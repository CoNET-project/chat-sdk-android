package network.conet.chat

import network.conet.chat.BeamioChatPgpStore.SiNode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Stored chain roster: PGP route keys per node, the legacy (keyless) roster, entry selection and the no-page listen
 * start. Synthetic IPs (TEST-NET-3) and a synthetic key body.
 */
class BeamioChatPgpStoreRosterTest {
    private val key = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nSYNTHETIC\n-----END PGP PUBLIC KEY BLOCK-----"

    @Test
    fun aLegacyRosterWithoutKeysLoadsWithEmptyKeysAndIsNotUsedAsAnEntry() {
        val legacy = """[{"ip":"203.0.113.10","domain":"a.example","region":"r1"}]"""
        val nodes = BeamioChatPgpStore.parseSiNodes(legacy)
        assertEquals(1, nodes.size)
        assertEquals("", nodes[0].armoredPublicKey)
        assertTrue(BeamioChatPgpStore.keyedEntries(nodes, emptySet()).isEmpty())
    }

    @Test
    fun keysSurviveAnEncodeDecodeRoundTrip() {
        val original = listOf(
            SiNode("203.0.113.10", "a.example", "r1", key),
            SiNode("203.0.113.11", "b.example", "r2", ""),
        )
        val back = BeamioChatPgpStore.parseSiNodes(BeamioChatPgpStore.encodeSiNodes(original))
        assertEquals(original, back)
    }

    @Test
    fun keyedEntriesSkipsKeylessNodesExcludedIpsInvalidIpsAndDuplicates() {
        val nodes = listOf(
            SiNode("203.0.113.10", "a", "", key),
            SiNode("203.0.113.11", "b", "", ""),
            SiNode("203.0.113.12", "c", "", key),
            SiNode("203.0.113.10", "dup", "", key),
            SiNode("not-an-ip", "d", "", key),
        )
        val out = BeamioChatPgpStore.keyedEntries(nodes, setOf("203.0.113.12"))
        assertEquals(listOf("203.0.113.10"), out.keys.toList())
        assertEquals("a", out.getValue("203.0.113.10").domain)
    }

    @Test
    fun backgroundListenStartsOnlyFromKeyedStoredNodes() {
        val started = BeamioChatPgpStore.noPageRoster(
            listOf(SiNode("203.0.113.10", "a", "", key), SiNode("203.0.113.11", "b", "", "")),
        )
        assertEquals(listOf("203.0.113.10"), started!!.map { it.ip })
    }

    @Test
    fun backgroundListenDoesNotStartWithoutAnyKeyedStoredNode() {
        assertNull(BeamioChatPgpStore.noPageRoster(listOf(SiNode("203.0.113.11", "b", "", ""))))
        assertNull(BeamioChatPgpStore.noPageRoster(emptyList()))
    }
}
