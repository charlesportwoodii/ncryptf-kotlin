package com.ncryptf.android.exceptions

/**
 * An exception thrown when the checksum attached to a v2 encrypted request is invalid
 * @property message Exception message
 */
class InvalidChecksumException(override var message:String): Exception(message)