package com.ncryptf.android.exceptions

/**
 * An exception thrown when signing fails
 * @property message Exception message
 */
class SigningException(override var message:String): Exception(message)