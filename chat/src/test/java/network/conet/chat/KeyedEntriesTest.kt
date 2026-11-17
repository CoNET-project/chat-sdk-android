package network.conet.chat

import network.conet.chat.BeamioConetChatModule.EntryPlan
import network.conet.chat.BeamioConetChatModule.Node
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Entry choice for a post and for the listen (3689188 `keyedEntries`, ported). Synthetic TEST-NET-3 IPs and a synthetic key.
 */
class KeyedEntriesTest {
    private val key = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nSYNTHETIC\n-----END PGP PUBLIC KEY BLOCK-----"

    @Test
    fun aKeylessNodeIsNeverAnEntry() {
        val nodes = listOf(Node("203.0.113.10", "a", "", ""), Node("203.0.113.11", "b", "", key))
        val out = BeamioConetChatModule.keyedEntries(nodes, emptySet())
        assertEquals(listOf("203.0.113.11"), out.map { it.ip })
    }

    @Test
    fun keyedEntriesSkipsExcludedInvalidAndDuplicateIps() {
        val nodes = listOf(
            Node("203.0.113.10", "a", "", key),
            Node("203.0.113.12", "c", "", key),
            Node("203.0.113.10", "dup", "", key),
            Node("not-an-ip", "d", "", key),
        )
        val out = BeamioConetChatModule.keyedEntries(nodes, setOf("203.0.113.12"))
        assertEquals(listOf("203.0.113.10"), out.map { it.ip })
        assertEquals("a", out.single().domain)
    }

    @Test
    fun noKeyedNodeGivesAnExplicitRefusalNotACandidate() {
        val keyless = listOf(Node("203.0.113.10", "a", "", ""))
        assertEquals(EntryPlan.Refused("no_entry_key"), BeamioConetChatModule.entryPlan(keyless, emptySet()))
        assertEquals(EntryPlan.Refused("no_entry_key"), BeamioConetChatModule.entryPlan(emptyList(), emptySet()))
    }

    @Test
    fun everyKeyedNodeExcludedGivesAnExplicitRefusal() {
        val nodes = listOf(Node("203.0.113.10", "a", "", key))
        assertEquals(EntryPlan.Refused("no_entry_key"), BeamioConetChatModule.entryPlan(nodes, setOf("203.0.113.10")))
    }

    @Test
    fun aKeyedNodeOutsideTheExclusionIsACandidate() {
        val nodes = listOf(Node("203.0.113.10", "a", "", key), Node("203.0.113.11", "b", "", key))
        val plan = BeamioConetChatModule.entryPlan(nodes, setOf("203.0.113.10"))
        assertTrue(plan is EntryPlan.Candidates)
        assertEquals(listOf("203.0.113.11"), (plan as EntryPlan.Candidates).nodes.map { it.ip })
    }
}
