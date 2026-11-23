package network.conet.chat.nativekey

import android.content.Context
import network.conet.chat.BeamioChatPgpStore

/**
 * Inbound PGP decryption from the shipped PGP store (2026-11-22). The shipped private armor (the legacy copy in
 * [BeamioChatPgpStore]) is read only and is the source for inbound decryption whenever it exists, even if the native PGP vault also holds
 * a record (the shipped store decides). Nothing here writes, imports, or removes the store, and no vault record is created.
 *
 * The shipped armor has no passphrase (the migration wrote it with an empty one), so decryption uses "". A key that needs a passphrase
 * fails closed (bad_passphrase).
 */
internal object LegacyPgpReader {

    /** The shipped private armor, read only; null when the store holds none or cannot be read (the caller then uses the vault). */
    internal fun shippedArmor(app: Context): String? = try {
        BeamioChatPgpStore.legacyPrivateArmorStrict(app)?.takeIf { it.contains("BEGIN PGP PRIVATE KEY") }
    } catch (_: Exception) {
        null
    }

    /** Decrypts [armored] with the shipped armor [legacyArmor]. Refusals as [NativePgp.decryptMessage]. */
    fun decryptWith(legacyArmor: String, armored: String): NativePgp.Outcome {
        val secret = NativePgp.parseSecret(legacyArmor) ?: return NativePgp.Outcome.fail("bad_pgp_key")
        return NativePgp.decryptMessage(secret, "", armored)
    }

    /** The literal of [armored] with the shipped armor [legacyArmor]. Refusals as [NativePgp.decryptLiteral]. */
    fun decryptLiteralWith(legacyArmor: String, armored: String): NativePgp.LiteralResult {
        val secret = NativePgp.parseSecret(legacyArmor) ?: return NativePgp.LiteralResult.fail("bad_pgp_key")
        return NativePgp.decryptLiteral(secret, "", armored)
    }

    /** The encryption subkey's key id (16 hex, upper case) of the shipped [armor], as the bridge checks the recipient; null when unparsable. */
    internal fun subkeyKeyIdHex(armor: String): String? =
        NativePgp.parseSecret(armor)?.let { NativePgpBackup.subkeyKeyId(it) }

    /**
     * The `pgpDecryptInbound` answer for the shipped armor [shipped] of the account [legacyEoa] (lower case), with the same checks as the
     * vault path (PgpDecryptInbound.answer). Read only.
     */
    fun inboundAnswer(shipped: String, legacyEoa: String, body: org.json.JSONObject): PgpDecryptInbound.Answer {
        val source = object : PgpDecryptInbound.Source {
            override fun subkeyKeyIdHex(): String? = LegacyPgpReader.subkeyKeyIdHex(shipped)
            override fun decryptLiteral(armoredMessage: String): NativePgp.LiteralResult = decryptLiteralWith(shipped, armoredMessage)
        }
        return PgpDecryptInbound.answer(body, legacyEoa, source)
    }
}
