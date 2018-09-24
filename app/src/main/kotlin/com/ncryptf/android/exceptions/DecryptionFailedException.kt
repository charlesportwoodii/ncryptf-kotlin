package com.ncryptf.android.exceptions

/**
 * An exception thrown when decryption of a message fails
 * @property message Exception message
 */
class DecryptionFailedException(override var message:String): Exception(message)