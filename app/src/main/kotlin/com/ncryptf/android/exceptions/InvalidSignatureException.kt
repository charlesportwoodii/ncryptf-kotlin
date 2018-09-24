package com.ncryptf.android.exceptions

/**
 * An exception thrown when the signature provided for the encrypted message is invalid
 * @property message Exception message
 */
class InvalidSignatureException(override var message:String): Exception(message)