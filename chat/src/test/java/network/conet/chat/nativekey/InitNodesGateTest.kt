package network.conet.chat.nativekey

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The nodes rule of `init` (PM R1841). The four cases of the decision table: an empty `nodes` array, a non-empty array,
 * a missing key with stored nodes, and a missing key with none stored.
 */
class InitNodesGateTest {
    @Test
    fun emptyNodesArrayIsUnavailableEvenWhenNodesAreStored() {
        // The stored count is not read when the key is present, so it cannot rescue an empty array.
        assertTrue(InitNodesGate.unavailable(nodesKeyPresent = true, payloadNodeCount = 0, storedNodeCount = 5))
        assertTrue(InitNodesGate.unavailable(nodesKeyPresent = true, payloadNodeCount = 0, storedNodeCount = 0))
    }

    @Test
    fun nonEmptyNodesArrayIsAvailable() {
        assertFalse(InitNodesGate.unavailable(nodesKeyPresent = true, payloadNodeCount = 3, storedNodeCount = 0))
    }

    @Test
    fun missingKeyWithStoredNodesIsAvailable() {
        assertFalse(InitNodesGate.unavailable(nodesKeyPresent = false, payloadNodeCount = 0, storedNodeCount = 4))
    }

    @Test
    fun missingKeyWithNothingStoredIsUnavailable() {
        assertTrue(InitNodesGate.unavailable(nodesKeyPresent = false, payloadNodeCount = 0, storedNodeCount = 0))
    }

    @Test
    fun codeIsTheSpecName() {
        assertTrue(InitNodesGate.NODES_UNAVAILABLE == "nodes_unavailable")
    }
}
