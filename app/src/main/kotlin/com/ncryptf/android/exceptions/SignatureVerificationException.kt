package com.ncryptf.android.exceptions

/**
 * An exception thrown when the signature provided with the encrypted payload is invalid
 * @property message Exception message
 */
class SignatureVerificationException(override var message:String): Exception(message)