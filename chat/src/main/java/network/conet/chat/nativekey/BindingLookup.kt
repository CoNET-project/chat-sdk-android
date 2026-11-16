package network.conet.chat.nativekey

/** The two query shapes of the binding lookup (§25.52Z.3, §25.52HH): a BeamioTag, or an EOA. */
internal enum class BindingKind { TAG, EOA }

/** The result of one registry read (§25.52HI.2). */
internal sealed class RegistryRead {
    /** A valid non-empty record. An EOA read carries no account; a tag read carries the bound EOA (lower case). */
    class Found(val eoa: String? = null) : RegistryRead()

    /** An explicit no-record answer: the exact AccountNotFound revert on an EOA read, or the zero address on a tag read (HH.4). */
    object Absent : RegistryRead()

    /** Anything else. [reason] is an internal code for the local log only; it never reaches the page (§25.52HI.4). */
    class Invalid(val reason: String) : RegistryRead()
}

/**
 * The read host of the binding lookup (§25.52HI.2): one read-only call on the current registry only, with no backup endpoint. [deadlineMs] is the
 * monotonic deadline of the whole lookup (§25.52HI.3). Implementations give [RegistryRead.Invalid] for every failure, and never throw.
 */
internal interface RegistryReader {
    fun readAccount(eoa: String, deadlineMs: Long): RegistryRead
    fun readOwner(tag: String, deadlineMs: Long): RegistryRead
}

/** The time budget of the lookup (§25.52HI.3, HH.5). */
internal object RegistryBudget {
    /** The total of the lookup: 10 000 ms. */
    const val TOTAL_MS: Long = 10_000L

    /** One read: at most 4 000 ms, and never more than what is left of the total. */
    const val PER_CALL_MS: Long = 4_000L

    /** The deadline of a lookup that starts at [startMs] (a monotonic clock reading). */
    fun deadlineFrom(startMs: Long): Long = startMs + TOTAL_MS

    /** The timeout of the next read: min(4 000 ms, remaining). Null when nothing is left (`budget_exceeded`: the read is not started). */
    fun perCallTimeout(deadlineMs: Long, nowMs: Long): Long? {
        val remaining = deadlineMs - nowMs
        return if (remaining <= 0L) null else minOf(PER_CALL_MS, remaining)
    }
}

/** The raw outcome of one read, as the transport and the decoder see it (§25.52HH.4). */
internal enum class RawOutcome {
    BOUND,
    ZERO_ADDRESS,
    REVERT_NOT_FOUND,
    REVERT_OTHER,
    REVERT_WITH_ARGS,
    REVERT_EMPTY,
    EXISTS_FALSE,
    EXISTS_TRUE_NAME_EMPTY,
    SEMANTIC_FAILED,
    TIMEOUT,
    RPC_ERROR,
    HTTP_ERROR,
    CONNECTION_REFUSED,
    TRUNCATED,
    DECODE_FAILED,
    NON_JSON,
    NO_RESULT,
}

/** The mapping of a raw outcome to a registry result (HH.4). Only the exact AccountNotFound revert of an EOA read is a no-record answer. */
internal object RegistryMapping {
    /** The selector of `AccountNotFound()`, with no arguments (§25.52HH.4). Compared in lower case. */
    const val ACCOUNT_NOT_FOUND_DATA = "0xfaba8ebe"

    fun map(kind: BindingKind, raw: RawOutcome): RegistryRead = when (raw) {
        RawOutcome.BOUND -> RegistryRead.Found(null)
        RawOutcome.ZERO_ADDRESS -> if (kind == BindingKind.TAG) RegistryRead.Absent else RegistryRead.Invalid("semantic_failed")
        RawOutcome.REVERT_NOT_FOUND -> if (kind == BindingKind.EOA) RegistryRead.Absent else RegistryRead.Invalid("revert_other")
        RawOutcome.REVERT_OTHER -> RegistryRead.Invalid("revert_other")
        RawOutcome.REVERT_WITH_ARGS -> RegistryRead.Invalid("revert_with_args")
        RawOutcome.REVERT_EMPTY -> RegistryRead.Invalid("revert_empty")
        RawOutcome.EXISTS_FALSE -> RegistryRead.Invalid("exists_false")
        RawOutcome.EXISTS_TRUE_NAME_EMPTY, RawOutcome.SEMANTIC_FAILED -> RegistryRead.Invalid("semantic_failed")
        RawOutcome.TIMEOUT -> RegistryRead.Invalid("timeout")
        RawOutcome.RPC_ERROR, RawOutcome.CONNECTION_REFUSED -> RegistryRead.Invalid("rpc_error")
        RawOutcome.HTTP_ERROR -> RegistryRead.Invalid("http_error")
        RawOutcome.TRUNCATED, RawOutcome.DECODE_FAILED, RawOutcome.NON_JSON, RawOutcome.NO_RESULT -> RegistryRead.Invalid("decode_failed")
    }

    /**
     * Classifies the error data of a revert (§25.52HH.4, r3kc): the data is compared exactly, after lower-casing. Only the selector alone is
     * AccountNotFound; the selector with anything after it is a revert with arguments, and any other selector is another revert.
     */
    fun classifyRevertData(data: String?): RawOutcome {
        val d = data?.lowercase()
        return when {
            d.isNullOrEmpty() || d == "0x" -> RawOutcome.REVERT_EMPTY
            d == ACCOUNT_NOT_FOUND_DATA -> RawOutcome.REVERT_NOT_FOUND
            d.startsWith(ACCOUNT_NOT_FOUND_DATA) -> RawOutcome.REVERT_WITH_ARGS
            else -> RawOutcome.REVERT_OTHER
        }
    }
}

/** The local sources of the EOA path (HH.2): a readable positive record, an unreadable one, or none. */
internal enum class LocalSource { NONE, POSITIVE, UNREADABLE }

/** The device facts of the create path (HH.2, BL-50): whether the account key K is present and whether a wallet private key record is. */
internal data class BindingDevice(val kPresent: Boolean = false, val walletRecord: Boolean = false)

/** The code of a binding lookup (§25.52Z.3, §25.46.6): `create` enters the first screen, the others do not enter creation. */
internal enum class BindingCode(val wire: String, val page: String, val creationEntered: Boolean) {
    CREATE("create", "first_screen", true),
    ALREADY_BOUND("already_bound", "nativeRecoveryOpen", false),
    LOOKUP_UNAVAILABLE("lookup_unavailable", "retry", false),
}

/**
 * The decision of the binding lookup (§25.52Z.3 items 1 to 3 and 6, §25.52HH.2 to HH.4, §25.52HI.3). Pure: the raw outcome, the total elapsed time,
 * the local source and the device facts are inputs, so the vectors can be checked without a network.
 *  - Over the total budget the result is `lookup_unavailable`, even for a positive record (BL-15, BL-16, BL-35).
 *  - A positive registry record is `already_bound` (BL-03, BL-04, BL-17, BL-51).
 *  - An explicit no-record answer creates, unless the local source is unreadable (BL-07, BL-18), or, on the tag path, the device holds K without a
 *    wallet record (BL-50, fail-closed).
 *  - Any other failure is `lookup_unavailable`. An EOA read with a positive local record is `already_bound` (BL-33); a tag read never takes the device
 *    as a positive source (BL-32, BL-34).
 */
internal object BindingDecision {
    fun decide(kind: BindingKind, raw: RawOutcome, totalMs: Long, local: LocalSource, device: BindingDevice): BindingCode =
        decideFromRead(kind, RegistryMapping.map(kind, raw), totalMs, local, device)

    /** The same decision from a registry result (the live reader gives this form). */
    fun decideFromRead(kind: BindingKind, reg: RegistryRead, totalMs: Long, local: LocalSource, device: BindingDevice): BindingCode {
        if (totalMs > RegistryBudget.TOTAL_MS) return BindingCode.LOOKUP_UNAVAILABLE
        return when (reg) {
            is RegistryRead.Found -> BindingCode.ALREADY_BOUND
            is RegistryRead.Absent -> when (kind) {
                BindingKind.TAG -> when {
                    local == LocalSource.UNREADABLE -> BindingCode.LOOKUP_UNAVAILABLE
                    device.kPresent && !device.walletRecord -> BindingCode.LOOKUP_UNAVAILABLE
                    else -> BindingCode.CREATE
                }
                BindingKind.EOA -> when (local) {
                    LocalSource.POSITIVE -> BindingCode.ALREADY_BOUND
                    LocalSource.UNREADABLE -> BindingCode.LOOKUP_UNAVAILABLE
                    LocalSource.NONE -> BindingCode.CREATE
                }
            }
            is RegistryRead.Invalid -> if (kind == BindingKind.EOA && local == LocalSource.POSITIVE) {
                BindingCode.ALREADY_BOUND
            } else {
                BindingCode.LOOKUP_UNAVAILABLE
            }
        }
    }
}
