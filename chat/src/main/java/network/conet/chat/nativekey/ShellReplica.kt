package network.conet.chat.nativekey

import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException

/**
 * The replica answer (§25.52T.3 末段, §25.52W.4, r3rv; vectors KR-01 to KR-07). When the native key store holds a readable EOA key but there is no
 * page copy, the copy is built from that key: the account is the key's own EOA, and no new key is ever generated.
 */
internal object ShellReplica {
    /** The answer: `ok` with the account, or not applied. */
    sealed class Answer {
        class Ok(val eoa: String) : Answer()
        object NotApplied : Answer()
    }

    /**
     * The production glue (KR-01): unlocks the readable keystore key through [unlock], answers, and zeroes the key bytes in every case.
     */
    fun fromUnlock(
        unlock: () -> ByteArray?,
        expectedEoa: String,
        outcome: ImportOutcome?,
        pointerSet: Boolean,
        store: SealedPageRecordStore,
        /**
         *  (parity, Y.163 第 32 项裁定 A): a page copy is made only for an account that holds a valid phrase. This is read before the key:
         * an account with no valid phrase (a key-only orphan) is not unlocked, not read and not derived. Returns the valid phrase's account, or null.
         */
        validPhraseOf: () -> String?,
    ): Answer {
        if (validPhraseOf()?.equals(expectedEoa, ignoreCase = true) != true) return Answer.NotApplied
        val key = unlock() ?: return Answer.NotApplied
        return try {
            answer(key, expectedEoa, outcome, pointerSet, store)
        } finally {
            key.fill(0)
        }
    }

    /**
     * Builds the copy from [key] when every condition holds: the legacy store is confirmed empty ([outcome] ABSENT), no pointer is set, no copy
     * exists, and the key derives [expectedEoa]. [key] is only read; the caller zeroes it. A missing key (unreadable or none) is not applied.
     */
    fun answer(key: ByteArray?, expectedEoa: String, outcome: ImportOutcome?, pointerSet: Boolean, store: SealedPageRecordStore): Answer {
        if (key == null) return Answer.NotApplied
        if (pointerSet || outcome != ImportOutcome.ABSENT) return Answer.NotApplied
        // The key must be the account's own key: a key that derives another address is not replicated (fail closed).
        val eoa = WalletAddress.fromPrivateKey(key)?.lowercase() ?: return Answer.NotApplied
        if (!eoa.equals(expectedEoa, ignoreCase = true)) return Answer.NotApplied
        return try {
            if (store.read() != null) return Answer.NotApplied
            val armor = "0x" + key.joinToString("") { "%02x".format(it) }
            val record = JSONObject()
                .put("rev", 1)
                .put("schemaVersion", ShellRecordPolicy.WALLET_SCHEMA_MIN)
                .put(
                    "profiles",
                    JSONArray().put(JSONObject().put("keyID", eoa).put("privateKeyArmor", armor)),
                )
            store.write(record)
            Answer.Ok(eoa)
        } catch (_: IOException) {
            Answer.NotApplied
        }
    }
}
