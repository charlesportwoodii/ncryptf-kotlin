package com.ncryptf.android.exceptions

/**
 * An exception thrown when encryption of a message fails
 * @property message Exception message
 */
class EncryptionFailedException(override var message:String): Exception(message)