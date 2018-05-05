package com.example.uberv.ndefreader

import android.nfc.NdefRecord

object NdefRecordUtils {
    @JvmField
    val RTD_AAR = "android.com:pkg".toByteArray()

    fun NdefRecord.getTypeLabel(): String {
        val type = this.type
        if (NdefRecord.RTD_URI!!.contentEquals(type)) {
            return "URI"
        } else if (NdefRecord.RTD_SMART_POSTER!!.contentEquals(type)) {
            return "Smart Poster"
        } else if (RTD_AAR.contentEquals(type)) {
            return "AAR"
        } else {
            return "Unknown"
        }
    }

    fun NdefRecord.getTnfLabel(): String =
            when (tnf) {
                NdefRecord.TNF_EMPTY -> "EMPTY"
                NdefRecord.TNF_ABSOLUTE_URI -> "ABSOLUTE URI"
                NdefRecord.TNF_EXTERNAL_TYPE -> "EXTERNAL TYPE"
                NdefRecord.TNF_MIME_MEDIA -> "MIME MEDIA"
                NdefRecord.TNF_UNCHANGED -> "UNCHANGED"
                NdefRecord.TNF_UNKNOWN -> "UNKNOWN"
                NdefRecord.TNF_WELL_KNOWN -> "WELL KNOWN"
                else -> "<Unhandled>"
            }
}