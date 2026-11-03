package network.conet.chat

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Own route vs chain. Fixtures: ROUTE_458 is the public route key of mailbox
 * node B6FF020087998A06 (#458, read from AddressPGP); ROUTE_OTHER is a made-up
 * key standing in for the stray mailbox (#234) of the RC3 Samsung run.
 */
class OwnRouteCheckTest {
    @Test
    fun routeKeyIdIsTheEncryptionSubkeyIdLikeTheChainRecord() {
        assertEquals("B6FF020087998A06", BeamioOwnRouteCheck.routeKeyId(ROUTE_458))
        assertEquals("F7FD9A642E5B8E42", BeamioOwnRouteCheck.routeKeyId(ROUTE_OTHER))
        assertEquals("B6FF020087998A06", BeamioOwnRouteCheck.routeKeyId(ROUTE_458.replace("\n", "\r\n")))
        assertEquals("", BeamioOwnRouteCheck.routeKeyId("not armor"))
    }

    @Test
    fun searchKeyCallDataHasNoFromAndTheRightSelector() {
        assertEquals(
            "0x052f2778000000000000000000000000abcdefabcdefabcdefabcdefabcdefabcdefabcd",
            BeamioOwnRouteCheck.searchKeyCallData("0xABCDEFabcdefABCDEFabcdefABCDEFabcdefABCD"),
        )
    }

    @Test
    fun decodesTheSearchKeyReply() {
        val ok = BeamioOwnRouteCheck.decodeSearchKeyResult(REPLY_OK)
        assertTrue(ok is BeamioOwnRouteCheck.ChainRoute.Ok)
        ok as BeamioOwnRouteCheck.ChainRoute.Ok
        assertEquals("B6FF020087998A06", ok.routeKeyId)
        assertEquals(ROUTE_458.replace("\r", "").trim(), ok.routeArmor)
        assertEquals(BeamioOwnRouteCheck.ChainRoute.Empty, BeamioOwnRouteCheck.decodeSearchKeyResult(REPLY_EMPTY))
        assertTrue(BeamioOwnRouteCheck.decodeSearchKeyResult("0x") is BeamioOwnRouteCheck.ChainRoute.Error)
        assertTrue(BeamioOwnRouteCheck.decodeSearchKeyResult("0x1234") is BeamioOwnRouteCheck.ChainRoute.Error)
    }

    @Test
    fun verdicts() {
        val chain458 = BeamioOwnRouteCheck.ChainRoute.Ok("B6FF020087998A06", ROUTE_458)
        assertEquals(BeamioOwnRouteCheck.Verdict.Match, BeamioOwnRouteCheck.verdict(ROUTE_458, chain458))
        val sw = BeamioOwnRouteCheck.verdict(ROUTE_OTHER, chain458)
        assertTrue(sw is BeamioOwnRouteCheck.Verdict.Switch)
        assertEquals("B6FF020087998A06", (sw as BeamioOwnRouteCheck.Verdict.Switch).routeKeyId)
        assertEquals(BeamioOwnRouteCheck.Verdict.NoRoute, BeamioOwnRouteCheck.verdict(ROUTE_458, BeamioOwnRouteCheck.ChainRoute.Empty))
        assertTrue(BeamioOwnRouteCheck.verdict(ROUTE_OTHER, BeamioOwnRouteCheck.ChainRoute.Error("x")) is BeamioOwnRouteCheck.Verdict.Retry)
    }

    /** Airplane mode: reads fail, the route is kept; back online the listen ends on the chain mailbox. */
    @Test
    fun airplaneModeThenOnlineEndsOnTheChainMailbox() {
        var listenRoute = ROUTE_OTHER
        val reads = ArrayDeque(
            listOf(
                BeamioOwnRouteCheck.ChainRoute.Error("UnknownHostException"),
                BeamioOwnRouteCheck.ChainRoute.Error("SocketTimeoutException"),
                BeamioOwnRouteCheck.ChainRoute.Ok("B6FF020087998A06", ROUTE_458),
            ),
        )
        val waits = mutableListOf<Long>()
        val routesSeenWhileOffline = mutableListOf<String>()
        val v = BeamioOwnRouteCheck.reconcile(
            listenArmor = { listenRoute },
            read = { reads.removeFirst() },
            sleep = { ms -> waits.add(ms); routesSeenWhileOffline.add(listenRoute); true },
        )
        assertEquals(listOf(5_000L, 15_000L), waits)
        // Offline: never moved anywhere (no random mailbox).
        assertTrue(routesSeenWhileOffline.all { it == ROUTE_OTHER })
        assertTrue(v is BeamioOwnRouteCheck.Verdict.Switch)
        listenRoute = (v as BeamioOwnRouteCheck.Verdict.Switch).routeArmor
        assertEquals(BeamioOwnRouteCheck.routeKeyId(ROUTE_458), BeamioOwnRouteCheck.routeKeyId(listenRoute))
        val again = BeamioOwnRouteCheck.reconcile({ listenRoute }, { BeamioOwnRouteCheck.ChainRoute.Ok("B6FF020087998A06", ROUTE_458) }, { true })
        assertEquals(BeamioOwnRouteCheck.Verdict.Match, again)
    }

    @Test
    fun aGoneSessionStopsRetrying() {
        var reads = 0
        val v = BeamioOwnRouteCheck.reconcile({ ROUTE_458 }, { reads++; BeamioOwnRouteCheck.ChainRoute.Error("x") }, { false })
        assertTrue(v is BeamioOwnRouteCheck.Verdict.Retry)
        assertEquals(1, reads)
    }

    @Test
    fun backoffCapsAtTheLastDelay() {
        val waits = mutableListOf<Long>()
        BeamioOwnRouteCheck.reconcile({ ROUTE_458 }, { BeamioOwnRouteCheck.ChainRoute.Error("x") }, { ms -> waits.add(ms); waits.size < 9 })
        assertEquals(listOf(5_000L, 15_000L, 30_000L, 60_000L, 120_000L, 300_000L, 300_000L, 300_000L, 300_000L), waits)
    }

    private companion object {
        val ROUTE_458 = """
-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEZp3vdxYJKwYBBAHaRw8BAQdAGUGtpw8DTkzeP5HIA62QAdPNZX8674gq
F1wqpEzggGrNKjB4NUUxRTRkNkVmYTRkMUNFM0VlQzYzRDk2NkU5NjQ5MWZC
ODMyNDJhZcKMBBAWCgA+BYJmne93BAsJBwgJkBeAVLUCJAlqAxUICgQWAAIB
AhkBApsDAh4BFiEEGsuJJxqeslcL0R5rF4BUtQIkCWoAAGQSAP9P+RFXYD8P
JiSP3+zyfhFK9ZcstUdCyymxnW65M2x42QEA28pbyM/L66lRJ1zA1cql8l2I
dPIeaij7rqopKo8YJAnOOARmne93EgorBgEEAZdVAQUBAQdAxWCQUUuSgg5Y
rLqzMa+C8NL4NMQf9ixKz4J4XxHVXFwDAQgHwngEGBYKACoFgmad73cJkBeA
VLUCJAlqApsMFiEEGsuJJxqeslcL0R5rF4BUtQIkCWoAAOr2AQDLIWLhsRVK
K9rf6dxPKWHGcNxyVG1VGMymdEMSIAdOgQD8CxJDw0add4iR4ba+nAcQmoqi
zGfvzu2ZQXFuN9xtYw0=
=B9Vx
-----END PGP PUBLIC KEY BLOCK-----
""".trimIndent()
        val ROUTE_OTHER = """
-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEaukAShYJKwYBBAHaRw8BAQdAYkk6/a+Fjt1a5I8BpxOWEvaax1m9pErK
L1RluivG17HNDHRlc3QtbWFpbGJveMLAEwQTFgoAhQWCaukASgMLCQcJEDK2
FFac0pL2RRQAAAAAABwAIHNhbHRAbm90YXRpb25zLm9wZW5wZ3Bqcy5vcmfJ
j/oUcKFqJKY8Qk4MeycVFuJN0MoSykr6Z3zNJUtC/AUVCggODAQWAAIBAhkB
ApsDAh4BFiEE+ft3E4HnRRleqqSiMrYUVpzSkvYAAGFgAP48WLrt8EeXe3vj
p0d4cDwSJGdYIdfbKFLgvjZmHxcjBgD/RafBeCv0KgQqy+bcv5EBg0PS3Kjs
BhNs/fEO5ZW5IQbOOARq6QBKEgorBgEEAZdVAQUBAQdALcIak9zoxib2ZMIy
x69lCmorhZ3FwU0FmUB5sK8PImgDAQgHwr4EGBYKAHAFgmrpAEoJEDK2FFac
0pL2RRQAAAAAABwAIHNhbHRAbm90YXRpb25zLm9wZW5wZ3Bqcy5vcmeRHSQp
rgL70A9/k6AhziPu0MtVrVSlDNDCu0JO/u0nMQKbDBYhBPn7dxOB50UZXqqk
ojK2FFac0pL2AAAM3gD/axUalNq0MOfsApR6iLd6RQCEubQiaOUo5bOMP6/z
7v4A/0pMJUMqf47xWM79nqKl7QEcNqeszcvrvrwBkpj/myQH
=lbNJ
-----END PGP PUBLIC KEY BLOCK-----
""".trimIndent()
        const val REPLY_OK = "0x00000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000000160000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000104431353343343239344239424442333100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000864584e6c63673d3d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010423646463032303038373939384130360000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003644c5330744c5331435255644a54694251523141675546564354456c44494574465753424354453944537930744c53307443677034616b3146576e417a646d52345755704c64316c43516b464959564a334f454a425557524252315648644842334f4552556133706c55445649535545324d6c46425a46424f576c67344e6a63305a33454b526a463363584246656d646e52334a4f533270434e4535565658685356464a72546d745762566c55556d744e5655354754544257624646365758705352477379546d74564e5535715554564e56317044436b394554586c4f5245706f576d4e4c54554a43515664445a304572516c6c4b6257356c4f544e4351584e4b516e646e536d74435a55465754465644536b46736355463456556c445a3146585155464a51677042614774435158427a5245466f4e454a476155564652334e31536b70346357567a62474e4d4d464931636b5930516c563055556c72513164765155464855564e4255446c514b314a4757466c454f46414b536d6c5455444d72656e6c6d61455a4c4f56706a633352565a454e3565573134626c63324e55307965445179555556424d6a6877596e6c4e4c3077324e6d7853536a46365154466a6357773462444a4a436d52515357566861576f33636e4676634574764f466c4b51573550543046536257356c4f544e465a323979516d6446525546615a465a42555656435156466b5158685851314656565856545a326331575170795448463654574572517a684f5444524f5456466d4f576c3453336f30536a52596545685757455a33524546525a306833626d644652304a5a5330464462305a6e6257466b4e7a4e6a536d74435a55454b566b7856513070426248464263484e4e526d6c465255647a6455704b6548466c6332786a544442534e584a474e454a566446464a61304e5862304642543349795156464554456c585447687a556c5a4c436b7335636d59325a4868515331644952324e4f65486c57527a4657523031356257524654564e4a515752505a3146454f454e34536b52334d47466b5a445270556a52695953747551574e52625739786151703652325a32656e5579576c4659526e564f4f5868305758637750516f39516a6c5765416f744c5330744c55564f52434251523141675546564354456c44494574465753424354453944537930744c53307443673d3d00000000000000000000000000000000000000000000000000000000"
        const val REPLY_EMPTY = "0x00000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    }
}
