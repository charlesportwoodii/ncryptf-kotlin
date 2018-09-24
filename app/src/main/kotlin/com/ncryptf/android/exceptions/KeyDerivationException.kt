package com.ncryptf.android.exceptions

/**
 * An exception thrown when a key cannot be created
 * @property message Exception message
 */
class KeyDerivationException(override var message:String): Exception(message)