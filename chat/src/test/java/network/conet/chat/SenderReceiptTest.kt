package network.conet.chat

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The sender delivery receipt, pure rules (shared vectors DR-01..18):
 * the whitelist, the setRoutes validation, the queue, the dedupe, the in-flight limit and the session binding. The bridge-level cases are in
 * [ReceiptBridgeTest]. Synthetic data, not device evidence.
 */
class SenderReceiptTest {
    private val me = "0x1111111111111111111111111111111111111111"
    private val peer = "0x2222222222222222222222222222222222222222"
    private val other = "0x3333333333333333333333333333333333333333"
    private val pgp = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nxxxx\n-----END PGP PUBLIC KEY BLOCK-----"

    private fun routeRow(address: String, user: String? = pgp, router: String? = pgp, field: String = "eoaAddress"): JSONObject {
        val o = JSONObject().put(field, address)
        if (user != null) o.put("userPublicKeyArmored", user)
        if (router != null) o.put("routerArmoredPublicKey", router)
        return o
    }

    /** A decrypted ordinary chat line: envelope{text = pending{sendId, from, text, createdAt}}. */
    private fun chatLine(sendId: String?, text: String = "hello", extra: (JSONObject) -> Unit = {}): String {
        val pending = JSONObject().put("from", "me").put("text", text).put("createdAt", 1L)
        if (sendId != null) pending.put("sendId", sendId)
        extra(pending)
        return JSONObject().put("timestamp", 1L).put("text", pending.toString()).put("from", peer).put("signMessage", "0xsig").toString()
    }

    /** A line whose pending message carries [inner] as its text. */
    private fun lineOf(inner: JSONObject, sendId: String = "own-id"): String {
        val pending = JSONObject().put("sendId", sendId).put("from", "me").put("text", inner.toString()).put("createdAt", 1L)
        return JSONObject().put("timestamp", 1L).put("text", pending.toString()).put("from", peer).put("signMessage", "0xsig").toString()
    }

    private fun reason(line: String): String = (SenderReceipt.classify(line) as SenderReceipt.Verdict.Reject).reason

    // ---- the whitelist (DR-02, 03, 04, 13, 18) ----------------------------------------------------------------------

    @Test
    fun anOrdinaryChatMessageIsWhitelistedWithItsSendId() {
        assertEquals("send-abc", (SenderReceipt.classify(chatLine("send-abc")) as SenderReceipt.Verdict.Ordinary).sendId)
        // a payment-card message has empty text and a paymentCard object; it is still chat
        val card = chatLine("s-card", text = "") { it.put("paymentCard", JSONObject().put("amount", "1")) }
        assertTrue(SenderReceipt.classify(card) is SenderReceipt.Verdict.Ordinary)
        // a text that is JSON without a type is still the user's text
        assertTrue(SenderReceipt.classify(chatLine("s-json", text = "{\"a\":1}")) is SenderReceipt.Verdict.Ordinary)
        // an envelope that carries the text under `message`
        val msg = JSONObject().put("message", JSONObject().put("sendId", "s-m").put("text", "x").toString()).put("signMessage", "0xsig").toString()
        assertTrue(SenderReceipt.classify(msg) is SenderReceipt.Verdict.Ordinary)
    }

    @Test
    fun aReceiptIsNotWhitelistedInAnyPosition() {
        val receipt = JSONObject().put("type", SenderReceipt.TYPE).put("sendId", "send-abc").put("armorHash", "h").put("deliveredAt", 2L).put("from", peer)
        assertEquals("receipt", reason(lineOf(receipt)))
        val asText = JSONObject().put("timestamp", 1L).put("text", receipt.toString()).put("from", peer).put("signMessage", "0xsig").toString()
        assertEquals("receipt", reason(asText))
        assertEquals("receipt", reason(receipt.toString()))
        // two levels down (text of the text)
        val deeper = JSONObject().put("text", receipt.toString())
        assertEquals("receipt", reason(lineOf(deeper)))
    }

    @Test
    fun callControlVoiceAndUnknownTypesAreNotWhitelisted() {
        for (type in listOf("voice_call_offer_v1", "voice_call_accept_v1", "voice_call_reject_v1", "voice_end_v1", "voice_call_timeout_v1", "voice_call_ringing_v1")) {
            val sig = JSONObject().put("type", type).put("callId", "call-0000000001").put("sessionId", "sess-0001").put("from", peer)
            assertEquals(type, "control", reason(lineOf(sig)))
        }
        for (type in listOf("voice_frame_v1", "voice_uplink", "voice_video_enable_v1", "voice_anything_v9")) {
            assertEquals(type, "voice", reason(lineOf(JSONObject().put("type", type).put("sessionId", "sess-0001"))))
        }
        // an unknown type, a system-looking type, a payment type: none is known chat, so none is answered
        for (type in listOf("beamio_something_new_v7", "system_notice", "reaction_v1", "recall_v1", "file_control_v1", "beamio_payme")) {
            assertEquals(type, "unknown_type", reason(lineOf(JSONObject().put("type", type).put("x", 1))))
        }
        // an untyped envelope whose pending message itself has a type
        val pending = JSONObject().put("type", "system_frame_v2").put("sendId", "s-sys").put("text", "hi").toString()
        val sys = JSONObject().put("timestamp", 1L).put("text", pending).put("from", peer).put("signMessage", "0xsig").toString()
        assertEquals("unknown_type", reason(sys))
    }

    @Test
    fun aCallSignalHiddenInBase64OrAnArrayIsNotWhitelisted() {
        val sig = JSONObject().put("type", "voice_end_v1").put("callId", "call-0000000001").put("sessionId", "sess-0001").put("from", peer).toString()
        val b64 = java.util.Base64.getEncoder().encodeToString(sig.toByteArray(Charsets.UTF_8))
        assertEquals("control", reason(chatLine("s-b64", text = b64)))
        assertEquals("control", reason(chatLine("s-arr", text = "[$sig]")))
        // an inner array with no signal is the user's text, not an exclusion
        assertTrue(SenderReceipt.classify(chatLine("s-arr2", text = "[1,2,3]")) is SenderReceipt.Verdict.Ordinary)
    }

    @Test
    fun groupMessagesAreNotWhitelisted() {
        assertEquals("group", reason(chatLine("s-g") { it.put("groupId", "g-1") }))
        val env = JSONObject(chatLine("s-g2")).put("groupId", "g-2").toString()
        assertEquals("group", reason(env))
    }

    @Test
    fun aMessageWithoutASendIdOrNotChatShapedIsNotWhitelisted() {
        assertEquals("no_send_id", reason(chatLine(null)))
        assertEquals("no_send_id", reason(chatLine("")))
        assertEquals("not_chat", reason("not json at all"))
        assertEquals("not_chat", reason("[]"))
        // the signed text is plain words, not a pending message
        assertEquals("not_chat", reason(JSONObject().put("text", "hello").put("signMessage", "0xsig").toString()))
        // a message with a sendId and no text field (the rule asks for no `text`) is still a message: it is judged by its own fields
        assertTrue(SenderReceipt.classify(JSONObject().put("text", JSONObject().put("sendId", "s").toString()).put("signMessage", "0xsig").toString()) is SenderReceipt.Verdict.Ordinary)
    }

    @Test
    fun wordsThatLookLikeATypeAreStillOrdinaryChat() {
        assertTrue(SenderReceipt.classify(chatLine("s-w", text = "voice_end_v1 is only words here")) is SenderReceipt.Verdict.Ordinary)
        assertTrue(SenderReceipt.classify(chatLine("s-w2", text = "type: beamio_chat_delivery_receipt_v1")) is SenderReceipt.Verdict.Ordinary)
    }

    // ---- the ordinary-message rule (DR-23..30) ----------------------------------------------------

    private fun envelopeOf(pending: JSONObject): String =
        JSONObject().put("timestamp", 1L).put("text", pending.toString()).put("from", peer).put("signMessage", "0xsig").toString()

    private fun ordinary(pending: JSONObject): Boolean = SenderReceipt.classify(envelopeOf(pending)) is SenderReceipt.Verdict.Ordinary

    private fun msg(sendId: String = "S1", text: String = "hi"): JSONObject = JSONObject().put("sendId", sendId).put("from", "me").put("text", text).put("createdAt", 1L)

    @Test
    fun dr23_dr24_dr25_dr26_dr27_textQuoteVoiceFilesAndPaymentCardsEarnReceipts() {
        assertTrue(ordinary(msg("S1")))
        // a quoted reply
        assertTrue(ordinary(msg("S2").put("quote", JSONObject().put("id", "q").put("text", "old").put("from", other))))
        // a voice message: the manifest's own type is nested and does not exclude it
        assertTrue(ordinary(msg("S3", "").put("voiceMessage", JSONObject().put("type", "voice_message_v1").put("fragmentHash", "ab").put("durationMs", 1200))))
        // images, video, PDF, an archive, a file with no media kind: all fileMessage
        for (kind in listOf("image", "video", "pdf", null)) {
            val f = JSONObject().put("type", "file_message_v1").put("name", "x")
            if (kind != null) f.put("mediaKind", kind)
            assertTrue("fileMessage $kind", ordinary(msg("S4-$kind", "").put("fileMessage", f)))
        }
        assertTrue(ordinary(msg("S4-zip", "").put("fileMessage", JSONObject().put("type", "file_message_v1").put("name", "a.zip"))))
        // a payment card
        assertTrue(ordinary(msg("S5", "").put("paymentCard", JSONObject().put("amount", "1"))))
        assertTrue("a payment card with no text field", ordinary(JSONObject().put("sendId", "S5b").put("from", "me").put("paymentCard", JSONObject())))
    }

    @Test
    fun dr28_reactionsRequestsCallRecordsTypedFramesAndGroupsEarnNone() {
        for (replyType in listOf("reaction", "paymentRequestCancel", "paymentRequestPaid")) {
            assertEquals(replyType, "reply", reason(envelopeOf(msg("S6-$replyType").put("reply", JSONObject().put("replyType", replyType)))))
        }
        assertEquals("call_record", reason(envelopeOf(msg("S7").put("callRecord", JSONObject().put("callId", "c")))))
        assertEquals("unknown_type", reason(envelopeOf(msg("S8").put("type", "anything"))))
        assertEquals("group", reason(envelopeOf(msg("S9").put("groupId", "g"))))
        // a null value is not "carries the field"
        assertTrue(ordinary(msg("S10").put("reply", JSONObject.NULL).put("groupId", JSONObject.NULL)))
    }

    @Test
    fun dr29_layersAreUnwrappedUpToSixAndEveryLayerIsChecked() {
        fun wrap(inner: JSONObject, sendId: String = "OUT"): JSONObject = JSONObject().put("sendId", sendId).put("text", inner.toString())
        val receipt = JSONObject().put("type", SenderReceipt.TYPE).put("sendId", "mine")
        // the inner layer is a receipt, or carries a reply: no receipt
        assertEquals("receipt", reason(envelopeOf(wrap(receipt))))
        assertEquals("reply", reason(envelopeOf(wrap(JSONObject().put("reply", JSONObject()).put("text", "x")))))
        // the inner layer is ordinary words: a receipt, with the FIRST layer's sendId
        val v = SenderReceipt.classify(envelopeOf(wrap(msg("IN", "plain words")))) as SenderReceipt.Verdict.Ordinary
        assertEquals("OUT", v.sendId)
        // an outer layer with no sendId: the inner layer's sendId does not stand in for it
        assertEquals("no_send_id", reason(envelopeOf(JSONObject().put("text", msg("IN2").toString()))))
        // depth: six layers are followed, the seventh refuses
        fun nest(layers: Int): JSONObject {
            var o = msg("LEAF", "words")
            for (i in 2..layers) o = JSONObject().put("sendId", "L$i").put("text", o.toString())
            return o
        }
        assertTrue("6 layers", ordinary(nest(6)))
        assertEquals("7 layers", "not_chat", reason(envelopeOf(nest(7))))
        // an exclusion in the sixth layer is still seen
        var deep = JSONObject().put("sendId", "D").put("text", "x").put("groupId", "g")
        for (i in 2..6) deep = JSONObject().put("sendId", "D$i").put("text", deep.toString())
        assertEquals("group", reason(envelopeOf(deep)))
    }

    @Test
    fun dr30_plainTextArraysEmptySendIdAndNonObjectsEarnNone() {
        assertEquals("not_chat", reason(JSONObject().put("text", "hello").put("signMessage", "0xsig").toString()))
        assertEquals("not_chat", reason(JSONObject().put("text", "[1,2]").put("signMessage", "0xsig").toString()))
        assertEquals("not_chat", reason(JSONObject().put("text", "{broken json").put("signMessage", "0xsig").toString()))
        assertEquals("no_send_id", reason(envelopeOf(msg("", "hi"))))
        assertEquals("no_send_id", reason(envelopeOf(JSONObject().put("text", "hi"))))
        assertEquals("no_send_id", reason(envelopeOf(JSONObject().put("sendId", 5).put("text", "hi"))))
        // user words that parse as a JSON scalar are still words
        assertTrue(ordinary(msg("S11", "5")))
        assertTrue(ordinary(msg("S12", "true")))
        assertTrue(ordinary(msg("S13", "{not json")))
    }

    // ---- the leaf and the depth (DR-31..35) --------------------------------------------------------

    private fun envelopeText(payload: String): String = JSONObject().put("timestamp", 1L).put("text", payload).put("from", peer).put("signMessage", "0xsig").toString()

    @Test
    fun dr31_theFirstLayerMustBeAMessageObject() {
        for (payload in listOf("[{\"sendId\":\"S\",\"text\":\"x\"}]", "\"just a string\"", "123", "true", "null", "plain words", "{broken")) {
            assertEquals(payload, "not_chat", reason(envelopeText(payload)))
        }
        // and an object with a sendId is the control case
        assertTrue(SenderReceipt.classify(envelopeText(msg("S").toString())) is SenderReceipt.Verdict.Ordinary)
    }

    @Test
    fun dr32_aDeeperTextThatIsNoObjectIsTheUsersWordsAndEarnsAReceipt() {
        for (text in listOf("[1,2]", "123", "true", "null", "plain", "{not json", "[]", "\"quoted\"", "")) {
            assertTrue("leaf '$text'", ordinary(JSONObject().put("sendId", "S").put("text", text)))
        }
        // an object leaf with no string text is a leaf too
        assertTrue(ordinary(JSONObject().put("sendId", "S").put("text", JSONObject().put("note", "x").toString())))
        assertTrue(ordinary(JSONObject().put("sendId", "S").put("text", JSONObject().put("text", 5).toString())))
    }

    private fun nestObjects(layers: Int, leaf: String = "plain words", innermost: (JSONObject) -> Unit = {}): JSONObject {
        var o = JSONObject().put("sendId", "L$layers").put("text", leaf).also(innermost)
        for (i in layers - 1 downTo 1) o = JSONObject().put("sendId", "L$i").put("text", o.toString())
        return o
    }

    @Test
    fun dr33_dr34_exactlySixObjectLayersEarnAReceiptAndTheSeventhDoesNot() {
        for (n in 1..6) {
            val v = SenderReceipt.classify(envelopeOf(nestObjects(n))) as SenderReceipt.Verdict.Ordinary
            assertEquals("$n layers: the first layer's sendId", "L1", v.sendId)
        }
        assertEquals("7 layers", "not_chat", reason(envelopeOf(nestObjects(7))))
        assertEquals("8 layers", "not_chat", reason(envelopeOf(nestObjects(8))))
        // the seventh layer decides even when the innermost text is a plain leaf, an array or a number
        for (leaf in listOf("plain", "[1]", "7")) assertEquals(leaf, "not_chat", reason(envelopeOf(nestObjects(7, leaf))))
        // six layers with a non-object leaf of every kind still earn a receipt
        for (leaf in listOf("plain", "[1]", "7", "null")) assertTrue(leaf, ordinary(nestObjects(6, leaf)))
    }

    @Test
    fun dr35_aReceiptInTheSixthOrSeventhLayerEarnsNothing() {
        val sixth = nestObjects(6) { it.remove("text"); it.put("type", SenderReceipt.TYPE).put("sendId", "mine") }
        assertEquals("receipt", reason(envelopeOf(sixth)))
        val seventh = nestObjects(7) { it.remove("text"); it.put("type", SenderReceipt.TYPE).put("sendId", "mine") }
        assertEquals("not_chat", reason(envelopeOf(seventh)))
        // a reply in the sixth layer
        val reply = nestObjects(6) { it.put("reply", JSONObject().put("replyType", "reaction")) }
        assertEquals("reply", reason(envelopeOf(reply)))
    }

    // ---- the envelope is no layer; the first layer has its own sendId (DR-36..38) ------------------

    @Test
    fun dr36_theSignedEnvelopeIsNotALayerSoSixObjectLayersInsideItEarnAReceipt() {
        // the real envelope, with its own fields, around a text that holds six object layers
        val six = nestObjects(6)
        val env = JSONObject().put("timestamp", 1L).put("text", six.toString()).put("from", peer).put("signMessage", "0xsig").toString()
        assertTrue(SenderReceipt.classify(env) is SenderReceipt.Verdict.Ordinary)
        val seven = nestObjects(7)
        assertEquals("not_chat", reason(JSONObject().put("timestamp", 1L).put("text", seven.toString()).put("from", peer).put("signMessage", "0xsig").toString()))
        // the envelope's own sendId, if a sender put one there, is not the first layer's
        val envWithId = JSONObject().put("sendId", "ENV").put("text", JSONObject().put("text", "x").toString()).put("signMessage", "0xsig").toString()
        assertEquals("no_send_id", reason(envWithId))
    }

    @Test
    fun dr37_aFirstLayerWithoutItsOwnSendIdEarnsNothingEvenIfAnInnerLayerHasOne() {
        val inner = JSONObject().put("sendId", "INNER").put("text", "words")
        assertEquals("no_send_id", reason(envelopeOf(JSONObject().put("text", inner.toString()))))
        assertEquals("no_send_id", reason(envelopeOf(JSONObject().put("sendId", "").put("text", inner.toString()))))
        assertEquals("no_send_id", reason(envelopeOf(JSONObject().put("sendId", 7).put("text", inner.toString()))))
        // with its own sendId the same shape is answered, and it is the first layer's
        val v = SenderReceipt.classify(envelopeOf(JSONObject().put("sendId", "FIRST").put("text", inner.toString()))) as SenderReceipt.Verdict.Ordinary
        assertEquals("FIRST", v.sendId)
    }

    @Test
    fun dr38_anEnvelopeTextThatIsNoObjectEarnsNothing() {
        assertEquals("not_chat", reason(envelopeText("plain words")))
        assertEquals("not_chat", reason(envelopeText("[1,2]")))
        assertEquals("not_chat", reason(envelopeText("[{\"sendId\":\"S\",\"text\":\"x\"}]")))
        assertEquals("not_chat", reason(JSONObject().put("timestamp", 1L).put("from", peer).put("signMessage", "0xsig").toString()))
    }

    // ---- an object leaf with an exclusion field is not a leaf (DR-39..41) -------------------------

    @Test
    fun dr39_anObjectLeafThatCarriesAnExclusionFieldEarnsNothing() {
        val cases = mapOf(
            "{\"type\":\"x\"}" to "unknown_type",
            "{\"groupId\":\"g\"}" to "group",
            "{\"reply\":{}}" to "reply",
            "{\"callRecord\":{}}" to "call_record",
        )
        for ((text, why) in cases) {
            assertEquals(text, why, reason(envelopeOf(JSONObject().put("sendId", "S").put("text", text))))
        }
        // with a string text of its own too, and at the innermost of six layers
        assertEquals("unknown_type", reason(envelopeOf(JSONObject().put("sendId", "S").put("text", JSONObject().put("type", "x").put("text", "hi").toString()))))
        assertEquals("unknown_type", reason(envelopeOf(nestObjects(6) { it.put("type", "x") })))
    }

    @Test
    fun dr40_anObjectLeafWithoutExclusionFieldsIsTheUsersTextAndEarnsAReceipt() {
        assertTrue(ordinary(JSONObject().put("sendId", "S").put("text", "{\"a\":1}")))
        assertTrue(ordinary(JSONObject().put("sendId", "S").put("text", "{}")))
        assertTrue(ordinary(JSONObject().put("sendId", "S").put("text", "{\"typeOf\":\"x\",\"replyTo\":1}")))
        // the exclusion fields mean a non-null value: null counts as absent
        assertTrue(ordinary(JSONObject().put("sendId", "S").put("text", "{\"type\":null,\"reply\":null}")))
    }

    @Test
    fun dr41_theInnermostObjectCountsAsALayer() {
        // six layers whose innermost (sixth) object is {"a":1}: a receipt
        var six = JSONObject().put("a", 1)
        for (i in 5 downTo 1) six = JSONObject().put("sendId", "L$i").put("text", six.toString())
        assertTrue(ordinary(six))
        // the sixth layer's text holds a seventh object {"a":1}: nothing
        var seven = JSONObject().put("a", 1)
        for (i in 6 downTo 1) seven = JSONObject().put("sendId", "L$i").put("text", seven.toString())
        assertEquals("not_chat", reason(envelopeOf(seven)))
    }

    // ---- "carries" means the key is present and its value is not null (DR-42..44) -----------------

    private fun leafText(text: String) = JSONObject().put("sendId", "S").put("text", text)

    @Test
    fun dr42_aNullValuedExclusionFieldIsNotCarried() {
        for (text in listOf("{\"type\":null}", "{\"reply\":null}", "{\"groupId\":null}", "{\"callRecord\":null}", "{\"type\":null,\"groupId\":null,\"reply\":null,\"callRecord\":null}")) {
            assertTrue("leaf $text", ordinary(leafText(text)))
        }
        // and on the first layer, in the envelope, and at the innermost of six layers
        assertTrue(ordinary(msg("S1").put("reply", JSONObject.NULL).put("callRecord", JSONObject.NULL).put("type", JSONObject.NULL).put("groupId", JSONObject.NULL)))
        assertTrue(SenderReceipt.classify(JSONObject(envelopeOf(msg("S2"))).put("groupId", JSONObject.NULL).put("type", JSONObject.NULL).toString()) is SenderReceipt.Verdict.Ordinary)
        assertTrue(ordinary(nestObjects(6) { it.put("type", JSONObject.NULL) }))
    }

    @Test
    fun dr43_anyNonNullValueOfAnExclusionFieldIsCarried() {
        val cases = mapOf(
            "{\"type\":\"\"}" to "unknown_type",
            "{\"type\":0}" to "unknown_type",
            "{\"type\":false}" to "unknown_type",
            "{\"reply\":{}}" to "reply",
            "{\"callRecord\":[]}" to "call_record",
            "{\"groupId\":\"\"}" to "group",
            "{\"groupId\":0}" to "group",
            "{\"reply\":false}" to "reply",
        )
        for ((text, why) in cases) assertEquals(text, why, reason(envelopeOf(leafText(text))))
        // the same on the first layer
        assertEquals("unknown_type", reason(envelopeOf(msg("S3").put("type", ""))))
        assertEquals("reply", reason(envelopeOf(msg("S4").put("reply", JSONObject()))))
        assertEquals("call_record", reason(envelopeOf(msg("S5").put("callRecord", JSONArray()))))
        assertEquals("group", reason(envelopeOf(msg("S6").put("groupId", ""))))
    }

    @Test
    fun dr44_keyNamesMatchExactlyAndWithCase() {
        for (text in listOf("{\"typeOf\":1}", "{\"Type\":\"x\"}", "{\"TYPE\":\"x\"}", "{\"GroupId\":\"g\"}", "{\"group_id\":\"g\"}", "{\"replyTo\":{}}", "{\"callrecord\":[]}", "{\" type\":\"x\"}")) {
            assertTrue("leaf $text", ordinary(leafText(text)))
        }
    }

    // ---- setRoutes validation (DR-10, 12, 15) ---------------------------------------------------------------------

    private fun body(routes: Any?, eoa: String? = me): JSONObject {
        val o = JSONObject().put("type", "setRoutes")
        if (routes != null) o.put("routes", routes)
        if (eoa != null) o.put("eoa", eoa)
        return o
    }

    private fun err(r: SenderReceipt.SetResult) = (r as SenderReceipt.SetResult.Err).code

    @Test
    fun setRoutesErrorsAreTypedAndEachOneIsAnswered() {
        assertEquals("not_ready", err(SenderReceipt.setRoutes(body(JSONArray()), null)))
        assertEquals("not_ready", err(SenderReceipt.setRoutes(body(JSONArray()), "  ")))
        assertEquals("bad_request", err(SenderReceipt.setRoutes(body("not an array"), me)))
        assertEquals("bad_request", err(SenderReceipt.setRoutes(body(null), me)))
        assertEquals("bad_request", err(SenderReceipt.setRoutes(body(JSONArray(), eoa = null), me)))
        assertEquals("bad_request", err(SenderReceipt.setRoutes(body(JSONArray(), eoa = " "), me)))
        assertEquals("signer_mismatch", err(SenderReceipt.setRoutes(body(JSONArray(), eoa = other), me)))
        val ok = SenderReceipt.setRoutes(body(JSONArray().put(routeRow(peer))), me) as SenderReceipt.SetResult.Ok
        assertEquals(1, ok.accepted)
        assertEquals(0, ok.dropped)
    }

    @Test
    fun theSessionAccountIsComparedInLowerCase() {
        val mixed = "0x" + me.substring(2).uppercase()
        assertTrue(SenderReceipt.setRoutes(body(JSONArray(), eoa = mixed), me) is SenderReceipt.SetResult.Ok)
        assertTrue(SenderReceipt.setRoutes(body(JSONArray(), eoa = me), mixed) is SenderReceipt.SetResult.Ok)
    }

    @Test
    fun badRowsAreDroppedOneByOneAndOversizeRefusesTheWholeCommand() {
        val rows = JSONArray()
            .put(routeRow(peer))
            .put(routeRow(other, user = "no key block"))
            .put(routeRow("0xnot-an-address"))
            .put(routeRow("0x4444444444444444444444444444444444444444", router = null))
            .put("a string row")
        val ok = SenderReceipt.setRoutes(body(rows), me) as SenderReceipt.SetResult.Ok
        assertEquals(1, ok.accepted)
        assertEquals(4, ok.dropped)
        assertEquals(setOf(peer), ok.routes.keys)
        // 257 rows: the whole command is refused
        val many = JSONArray()
        for (i in 0 until 257) many.put(routeRow("0x" + i.toString(16).padStart(40, '0')))
        assertEquals("bad_request", err(SenderReceipt.setRoutes(body(many), me)))
        // 256 rows are fine
        val max = JSONArray()
        for (i in 0 until 256) max.put(routeRow("0x" + i.toString(16).padStart(40, '0')))
        assertEquals(256, (SenderReceipt.setRoutes(body(max), me) as SenderReceipt.SetResult.Ok).accepted)
        // an armor over 32 KB, in either key: the whole command is refused
        val big = pgp + "x".repeat(32 * 1024)
        assertEquals("bad_request", err(SenderReceipt.setRoutes(body(JSONArray().put(routeRow(peer)).put(routeRow(other, user = big))), me)))
        assertEquals("bad_request", err(SenderReceipt.setRoutes(body(JSONArray().put(routeRow(peer, router = big))), me)))
        // exactly 32 KB is allowed
        val edge = pgp + "x".repeat(32 * 1024 - pgp.length)
        assertEquals(32 * 1024, edge.toByteArray().size)
        assertTrue(SenderReceipt.setRoutes(body(JSONArray().put(routeRow(peer, user = edge))), me) is SenderReceipt.SetResult.Ok)
    }

    @Test
    fun theSizeLimitCountsBytesNotCharacters() {
        val wide = pgp + "é".repeat(17 * 1024) // 2 bytes each: over 34 KB of bytes, 17 K characters
        assertEquals("bad_request", err(SenderReceipt.setRoutes(body(JSONArray().put(routeRow(peer, user = wide))), me)))
    }

    @Test
    fun theAddressKeysAndTheLaterRowWins() {
        val rows = JSONArray()
            .put(routeRow("0x" + peer.substring(2).uppercase(), field = "eoa"))
            .put(routeRow(other, field = "address"))
            .put(routeRow(peer, user = pgp + "\nSECOND"))
        val ok = SenderReceipt.setRoutes(body(rows), me) as SenderReceipt.SetResult.Ok
        assertEquals(setOf(peer, other), ok.routes.keys)
        assertTrue(ok.routes.getValue(peer).getString("userPublicKeyArmored").endsWith("SECOND"))
        // a stored route has the three fields only
        assertEquals(setOf("eoaAddress", "userPublicKeyArmored", "routerArmoredPublicKey"), ok.routes.getValue(peer).keys().asSequence().toSet())
    }

    // ---- the pipeline ---------------------------------------------------------------------------------------------

    private class Rig(
        val own: String,
        var alive: Boolean = true,
        var now: Long = 1_700_000_000_000L,
    ) {
        val queue = ArrayList<Runnable>()
        val sent = ArrayList<Pair<JSONObject, String>>()
        val dones = ArrayList<() -> Unit>()
        val logs = ArrayList<String>()
        var maxInFlight = 0
        var throwOnSend = false
        lateinit var p: SenderReceipt.Pipeline

        fun build(): Rig {
            p = SenderReceipt.Pipeline(
                execute = { queue.add(it) },
                alive = { alive },
                ownEoa = { own },
                send = { route, payload, done ->
                    if (throwOnSend) throw IllegalStateException("boom")
                    sent.add(route to payload)
                    dones.add(done)
                    maxInFlight = maxOf(maxInFlight, p.inFlightCount())
                },
                log = { logs.add(it) },
                nowMs = { now },
                newId = { "fixed-id" },
            )
            return this
        }

        /** Runs every queued job (jobs may add jobs). */
        fun drain() {
            while (queue.isNotEmpty()) queue.removeAt(0).run()
        }
    }

    private fun rig() = Rig(me).build()

    private fun table(vararg addresses: String): Map<String, JSONObject> =
        (SenderReceipt.setRoutes(body(JSONArray().also { a -> addresses.forEach { a.put(routeRow(it)) } }), me) as SenderReceipt.SetResult.Ok).routes

    @Test
    fun dr01_withARouteAnOrdinaryMessageEarnsOneReceiptWithItsSendId() {
        val r = rig()
        r.p.setRoutes(table(peer))
        assertEquals("queued", r.p.onAcked(chatLine("S1"), "hash-1", peer))
        assertTrue("the worker has not run: the caller only handed it over", r.sent.isEmpty())
        r.drain()
        assertEquals(1, r.sent.size)
        assertEquals(peer, r.sent[0].first.getString("eoaAddress"))
        val outer = JSONObject(r.sent[0].second)
        assertEquals("S1", JSONObject(outer.getString("text")).getString("sendId"))
    }

    @Test
    fun dr14_theReceiptPayloadShape() {
        val r = rig()
        r.p.setRoutes(table(peer))
        r.p.onAcked(chatLine("S-14", text = "secret words"), "hash-14", peer)
        r.drain()
        val payload = r.sent.single().second
        val outer = JSONObject(payload)
        assertEquals(setOf("sendId", "from", "text", "createdAt"), outer.keys().asSequence().toSet())
        assertEquals("fixed-id", outer.getString("sendId"))
        assertEquals("me", outer.getString("from"))
        assertEquals(1_700_000_000_000L, outer.getLong("createdAt"))
        val inner = JSONObject(outer.getString("text"))
        assertEquals(setOf("type", "sendId", "armorHash", "deliveredAt", "from"), inner.keys().asSequence().toSet())
        assertEquals("beamio_chat_delivery_receipt_v1", inner.getString("type"))
        assertEquals("S-14", inner.getString("sendId"))
        assertEquals("hash-14", inner.getString("armorHash"))
        assertEquals(1_700_000_000_000L, inner.getLong("deliveredAt"))
        assertEquals(me, inner.getString("from"))
        assertTrue("no message text in the receipt", !payload.contains("secret words"))
    }

    @Test
    fun dr05_theSameArmorHashEarnsOneReceipt() {
        val r = rig()
        r.p.setRoutes(table(peer))
        assertEquals("queued", r.p.onAcked(chatLine("S5"), "hash-5", peer))
        assertEquals("already_receipted", r.p.onAcked(chatLine("S5"), "hash-5", peer))
        // even a different sendId under the same armor is the same copy
        assertEquals("already_receipted", r.p.onAcked(chatLine("S5b"), "hash-5", peer))
        r.drain()
        assertEquals(1, r.sent.size)
    }

    @Test
    fun dr16_theSameFromAndSendIdWithAnotherArmorEarnsOneReceipt() {
        val r = rig()
        r.p.setRoutes(table(peer, other))
        assertEquals("queued", r.p.onAcked(chatLine("S16"), "armor-A", peer))
        assertEquals("already_receipted", r.p.onAcked(chatLine("S16"), "armor-B", peer))
        assertEquals("already_receipted", r.p.onAcked(chatLine("S16"), "armor-C", peer))
        // the same sendId from another sender is another message
        assertEquals("queued", r.p.onAcked(chatLine("S16"), "armor-D", other))
        r.drain()
        assertEquals(2, r.sent.size)
    }

    @Test
    fun dr16_theDedupeSetsHoldAtMost1024AndDropTheOldest() {
        val r = rig()
        for (i in 0 until 1025) r.p.onAcked(chatLine("S-$i"), "armor-$i", peer)
        // the first pair was dropped from the sets: it is a new message again; the last one is still remembered
        assertEquals("queued", r.p.onAcked(chatLine("S-0"), "armor-new-0", peer))
        assertEquals("already_receipted", r.p.onAcked(chatLine("S-1024"), "armor-new-1024", peer))
    }

    @Test
    fun dr06_dr07_noRouteQueuesAndALaterSetRoutesSendsIt() {
        val r = rig()
        assertEquals("queued", r.p.onAcked(chatLine("S6"), "hash-6", peer))
        r.drain()
        assertTrue(r.sent.isEmpty())
        assertEquals(1, r.p.queueSize())
        // routes for someone else do not release it
        r.p.setRoutes(table(other))
        r.drain()
        assertTrue(r.sent.isEmpty())
        assertEquals(1, r.p.queueSize())
        // the sender arrives: sent at once, the queue is empty
        r.p.setRoutes(table(other, peer))
        r.drain()
        assertEquals(1, r.sent.size)
        assertEquals(0, r.p.queueSize())
        // a further setRoutes does not send it again
        r.p.setRoutes(table(peer))
        r.drain()
        assertEquals(1, r.sent.size)
    }

    @Test
    fun dr08_aQueuedReceiptIsDroppedAfterTenMinutes() {
        val r = rig()
        r.p.onAcked(chatLine("S8"), "hash-8", peer)
        r.now += SenderReceipt.QUEUE_TTL_MS - 1
        r.p.setRoutes(table(peer)) // just inside the TTL: goes
        r.drain()
        assertEquals(1, r.sent.size)

        val r2 = rig()
        r2.p.onAcked(chatLine("S8"), "hash-8", peer)
        r2.now += SenderReceipt.QUEUE_TTL_MS
        r2.p.setRoutes(table(peer))
        r2.drain()
        assertTrue(r2.sent.isEmpty())
        assertEquals(0, r2.p.queueSize())
        assertTrue(r2.logs.any { it.startsWith("[send] kind=receipt dropped=expired") })
    }

    @Test
    fun dr09_theQueueKeepsTheNewest128() {
        val r = rig()
        for (i in 0 until 129) assertEquals("queued", r.p.onAcked(chatLine("S9-$i"), "hash-9-$i", peer))
        assertEquals(128, r.p.queueSize())
        // the oldest (index 0) was dropped; the rest go once the route arrives, two at a time
        r.p.setRoutes(table(peer))
        while (r.queue.isNotEmpty() || r.dones.isNotEmpty()) {
            r.drain()
            r.dones.toList().also { r.dones.clear() }.forEach { it() }
        }
        val ids = r.sent.map { JSONObject(JSONObject(it.second).getString("text")).getString("sendId") }
        assertEquals(128, ids.size)
        assertTrue(!ids.contains("S9-0"))
        assertEquals("S9-1", ids.first())
        assertEquals("S9-128", ids.last())
    }

    @Test
    fun dr17_atMostTwoReceiptsAreInFlightAndAllOfThemGoOut() {
        val r = rig()
        r.p.setRoutes(table(peer))
        for (i in 0 until 5) r.p.onAcked(chatLine("S17-$i"), "hash-17-$i", peer)
        r.drain()
        assertEquals("two slots", 2, r.sent.size)
        assertEquals(2, r.p.inFlightCount())
        assertEquals(3, r.p.queueSize())
        // one finishes: the next starts, never more than two at once
        r.dones.removeAt(0)()
        r.drain()
        assertEquals(3, r.sent.size)
        assertEquals(2, r.p.inFlightCount())
        while (r.dones.isNotEmpty()) {
            r.dones.removeAt(0)()
            r.drain()
        }
        assertEquals(5, r.sent.size)
        assertEquals(0, r.p.inFlightCount())
        assertEquals(0, r.p.queueSize())
        assertTrue("never more than two in flight", r.maxInFlight <= 2)
    }

    @Test
    fun aDoneCalledTwiceFreesOnlyOneSlot() {
        val r = rig()
        r.p.setRoutes(table(peer))
        for (i in 0 until 4) r.p.onAcked(chatLine("S-$i"), "h-$i", peer)
        r.drain()
        val first = r.dones[0]
        first(); first(); first()
        r.drain()
        assertEquals("one slot freed once: one more started", 3, r.sent.size)
        assertEquals(2, r.p.inFlightCount())
    }

    @Test
    fun aSendThatNeverReportsIsReleasedAfterItsStaleTime() {
        val r = rig()
        r.p.setRoutes(table(peer))
        for (i in 0 until 3) r.p.onAcked(chatLine("S-$i"), "h-$i", peer)
        r.drain()
        assertEquals(2, r.sent.size) // both slots are held, and they never report
        r.now += SenderReceipt.IN_FLIGHT_STALE_MS
        r.p.setRoutes(table(peer)) // any pump
        r.drain()
        assertEquals(3, r.sent.size)
    }

    @Test
    fun dr18_nothingOutsideTheWhitelistEarnsAReceiptAndTheControlGroupStillDoes() {
        val r = rig()
        r.p.setRoutes(table(peer))
        val receipt = lineOf(JSONObject().put("type", SenderReceipt.TYPE).put("sendId", "mine").put("from", peer))
        val control = lineOf(JSONObject().put("type", "voice_end_v1").put("callId", "call-0000000001").put("sessionId", "sess-0001").put("from", peer))
        val voice = lineOf(JSONObject().put("type", "voice_frame_v1").put("sessionId", "sess-0001"))
        val unknown = lineOf(JSONObject().put("type", "mystery_v3"))
        val system = lineOf(JSONObject().put("type", "system_notice").put("text", "x"))
        for ((i, line) in listOf(receipt, control, voice, unknown, system).withIndex()) {
            val out = r.p.onAcked(line, "hash-18-$i", peer)
            assertTrue("$i answered $out", out in setOf("receipt", "control", "voice", "unknown_type"))
        }
        r.drain()
        assertTrue(r.sent.isEmpty())
        assertEquals(0, r.p.queueSize())
        // control group
        assertEquals("queued", r.p.onAcked(chatLine("S18"), "hash-18-ok", peer))
        r.drain()
        assertEquals(1, r.sent.size)
    }

    @Test
    fun dr13_aMessageWithoutASendIdEarnsNoReceiptAndIsNotQueued() {
        val r = rig()
        assertEquals("no_send_id", r.p.onAcked(chatLine(null), "hash-13", peer))
        assertEquals(0, r.p.queueSize())
    }

    @Test
    fun aMessageFromTheAccountItselfEarnsNoReceipt() {
        val r = rig()
        assertEquals("self", r.p.onAcked(chatLine("s"), "h", me))
        assertEquals("no_sender", r.p.onAcked(chatLine("s"), "h", " "))
    }

    @Test
    fun dr11_clearDropsRoutesQueueAndTheDedupeSetsAndNothingIsSentAfter() {
        val r = rig()
        r.p.setRoutes(table(peer))
        for (i in 0 until 3) r.p.onAcked(chatLine("S11-$i"), "hash-11-$i", peer)
        r.p.onAcked(chatLine("S11-q"), "hash-11-q", other) // queued: no route for other
        r.p.clear()
        assertEquals(0, r.p.routeCount())
        assertEquals(0, r.p.queueSize())
        assertEquals("the two jobs already handed to the worker still hold their slots", 2, r.p.inFlightCount())
        r.drain() // the jobs handed to the worker before the clear find the session gone
        assertEquals("and free them when they end", 0, r.p.inFlightCount())
        assertTrue(r.sent.isEmpty())
        assertTrue(r.logs.contains("[send] kind=receipt skip=session_ended"))
        // routes are empty: a new message queues and nothing goes without a new setRoutes
        assertEquals("queued", r.p.onAcked(chatLine("S11-new"), "hash-11-new", peer))
        r.drain()
        assertTrue(r.sent.isEmpty())
        // the dedupe sets are empty again too
        assertEquals("queued", r.p.onAcked(chatLine("S11-0"), "hash-11-0", peer))
    }

    @Test
    fun nothingIsSentWhenTheSessionIsNoLongerTheCurrentOne() {
        val r = rig()
        r.p.setRoutes(table(peer))
        r.p.onAcked(chatLine("S-gone"), "h-gone", peer)
        r.alive = false // another account took over before the worker ran
        r.drain()
        assertTrue(r.sent.isEmpty())
        assertEquals("[send] kind=receipt skip=session_ended", r.logs.last())
        assertEquals("the slot was freed", 0, r.p.inFlightCount())
    }

    @Test
    fun aFailingSendIsLoggedFreesItsSlotAndDoesNotEscapeTheWorker() {
        val r = rig()
        r.throwOnSend = true
        r.p.setRoutes(table(peer))
        r.p.onAcked(chatLine("S-boom"), "h-boom", peer)
        r.drain()
        assertTrue(r.logs.any { it.startsWith("[send] kind=receipt failed=IllegalStateException") })
        assertEquals(0, r.p.inFlightCount())
    }

    @Test
    fun concurrentAckedSetRoutesAndClearKeepTheLimits() {
        val sent = java.util.concurrent.atomic.AtomicInteger()
        val inFlight = java.util.concurrent.atomic.AtomicInteger()
        val maxSeen = java.util.concurrent.atomic.AtomicInteger()
        val pool = java.util.concurrent.Executors.newFixedThreadPool(8)
        val p = SenderReceipt.Pipeline(
            execute = { pool.execute(it) },
            alive = { true },
            ownEoa = { me },
            send = { _, _, done ->
                val n = inFlight.incrementAndGet()
                maxSeen.accumulateAndGet(n) { a, b -> maxOf(a, b) }
                sent.incrementAndGet()
                pool.execute { Thread.sleep(1); inFlight.decrementAndGet(); done() }
            },
            log = {},
        )
        val tbl = table(peer)
        val threads = (0 until 4).map { t ->
            Thread {
                for (i in 0 until 200) {
                    p.onAcked(chatLine("C-$t-$i"), "armor-$t-$i", peer)
                    if (i % 25 == 0) p.setRoutes(tbl)
                    if (t == 0 && i % 60 == 59) p.clear()
                }
            }.also { it.start() }
        }
        threads.forEach { it.join() }
        p.setRoutes(tbl)
        Thread.sleep(300)
        pool.shutdown()
        assertTrue(pool.awaitTermination(20, java.util.concurrent.TimeUnit.SECONDS))
        assertTrue("in flight never above 2 (saw ${maxSeen.get()})", maxSeen.get() <= 2)
        assertTrue(sent.get() > 0)
    }

    // ---- the session ------------------------------------------------------------------------------------------------

    @Test
    fun endingASessionClearsItsReceiptsAndPendingMessages() {
        val s = BeamioConetChatModule.Session()
        s.eoa = me
        s.receipts.setRoutes(table(peer))
        s.pendingAcks["h1"] = BeamioConetChatModule.PendingAck(chatLine("s-1"), peer, "d", 1L)
        s.clearReceiptState()
        assertEquals(0, s.receipts.routeCount())
        assertEquals(0, s.receipts.queueSize())
        assertTrue(s.pendingAcks.isEmpty())
        assertNull(s.pendingAcks["h1"])
    }
}
