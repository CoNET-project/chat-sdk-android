package network.conet.chat.localread

import java.io.File

/** Test store on an in-memory SQLite database (xerial sqlite-jdbc). */
fun newTestStore(account: String, parser: ((ByteArray) -> ParsedBody)? = MediaManifestParser::parse): LocalChatStore =
    LocalChatStore(account, JdbcSqlDb.memory(), parser)

/** Test store on a file database (survives lock and reopen). */
fun newFileStore(account: String, file: File): LocalChatStore =
    LocalChatStore(account, JdbcSqlDb.open(file), MediaManifestParser::parse)
