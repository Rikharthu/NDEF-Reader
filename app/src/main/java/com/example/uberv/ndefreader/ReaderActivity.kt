package com.example.uberv.ndefreader

import android.app.PendingIntent
import android.content.Intent
import android.content.IntentFilter
import android.nfc.NdefMessage
import android.nfc.NdefRecord
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.nfc.tech.MifareUltralight
import android.nfc.tech.Ndef
import android.nfc.tech.NfcA
import android.os.Bundle
import android.support.v7.app.AppCompatActivity
import android.support.v7.widget.LinearLayoutManager
import kotlinx.android.synthetic.main.activity_main.*
import timber.log.Timber
import java.nio.charset.Charset
import java.util.*
import kotlin.experimental.and

class ReaderActivity : AppCompatActivity() {

    private var nfcAdapter: NfcAdapter? = null
    private var isInReadMode = false
    private lateinit var adapter: NdefRecordAdapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        nfcAdapter = NfcAdapter.getDefaultAdapter(this)
        adapter = NdefRecordAdapter()
        recycler.layoutManager = LinearLayoutManager(this, LinearLayoutManager.VERTICAL, false)
        recycler.adapter = adapter
    }

    override fun onNewIntent(intent: Intent) {
        Timber.d("onNewIntent " + intent.action + ", " + isInReadMode)
        if (isInReadMode && NfcAdapter.ACTION_TAG_DISCOVERED == intent.action) {
            Timber.d("Time to write NFC")
            val tag = intent.getParcelableExtra<Tag>(NfcAdapter.EXTRA_TAG)
            if (tag != null) {
                onTagDiscovered(tag)
            }
            tag.techList
        }
        val data = intent.data
        Timber.d("Intent data: $data")
    }

    private fun onTagDiscovered(tag: Tag) {
        Timber.d("Discovered tag: $tag")
        val ndef = Ndef.get(tag)
        if (ndef != null) {
            onNdefDiscovered(ndef)
        }
    }

    private fun onIsoDepDiscovered(isoDep: IsoDep) {
        isoDep.connect()
        val bytes = isoDep.historicalBytes
        isoDep.close()
    }

    private fun onNfcaDiscovered(nfca: NfcA) {
        nfca.connect()

        nfca.close()
    }

    private fun onMifareDiscovered(mifare: MifareUltralight) {
        mifare.connect()
        mifare.type
        val type = when (mifare.type) {
            MifareUltralight.TYPE_ULTRALIGHT -> "Ultralight"
            MifareUltralight.TYPE_ULTRALIGHT_C -> "Ultralight-C"
            MifareUltralight.TYPE_UNKNOWN -> "Unknown"
            else -> "Unknown"
        }
        /*
        val pageOffset = 20
        val data1 = mifare.readPages(pageOffset).slice(0..3).toByteArray()
        val cmd = byteArrayOf(0x30, pageOffset.toByte())
        val data1Transceived = mifare.transceive(cmd).slice(0..3).toByteArray()
        val authPage = mifare.readPages(40)
        mifare.writePage(pageOffset, byteArrayOf(1, 2, 3, 4))
        val data2 = mifare.readPages(pageOffset).slice(0..3).toByteArray()
        Timber.d("Mifare is of type: $type")
        Timber.d("data1=${Arrays.toString(data1)}, data1Transceived=${Arrays.toString(data1Transceived)}, data2=${Arrays.toString(data2)}, authPages=${Arrays.toString(authPage)}")
        */

        // Page = 4 bytes, each read operation reads 4 pages
        var data = ByteArray(4 * 4 * 128)
        for (i in 0 until 48 step 4) {
            try {
                val pages = mifare.readPages(i)
                for (j in 0 until 16) {
                    data[i + j] = pages[j]
                }
            } catch (err: Exception) {
                Timber.e(err, "At page=$i")
                data = data.sliceArray(0..i * 4 * 4)
                break
            }
        }
        val tmp = Arrays.toString(data)

        // More info: page 18 of https://www.nxp.com/docs/en/data-sheet/NTAG213_215_216.pdf
//        val auth0 = mifare.readPages(0x29).sliceArray(0..3)
        val auth0 = mifare.readPages(0x29)[3]
        val pwd = mifare.readPages(0x2b).sliceArray(0..3)
        val access = mifare.readPages(0x2A)[0]
        val cfglck1 = access and 0b01000000
        val cfglck2 = access and 0b00000010
        Timber.d("access: $access")
        // Section 8.5.1 of  https://www.nxp.com/docs/en/data-sheet/NTAG213_215_216.pdf
        val uid = mifare.readPages(0).sliceArray(0 until 8)
        val checkByte0 = uid[0]
        Timber.d("UID: ${uid.toHexString()}")
        Timber.d("Check byte 0: $checkByte0")

        val version = mifare.transceive(byteArrayOf(0x60))
        Timber.d("Version: ${version.toHexString()}")
        val storageSizeBytes = when (version[6]) {
            0x0F.toByte() -> 144
            0x11.toByte() -> 504
            0x13.toByte() -> 888
            else -> -1
        }
        Timber.d("Storage size bytes: $storageSizeBytes")

        val signature = mifare.transceive(byteArrayOf(0x3C, 0x00))
        Timber.d("Signature: ${signature.toHexString()}")

        if (auth0 == 0xff.toByte()) {
            Timber.d("Auth0 disabled: $auth0")
        } else {
            Timber.d("Auth0 enabled: $auth0")
        }
        Timber.d("pwd page: ${Arrays.toString(pwd)}")
        Timber.d("Mifare data (HEX): ${data.toHexString()}")
        Timber.d("Mifare data (ASCII): ${String(data)}")

        val otpPage = mifare.readPages(0x02).sliceArray(0x02..0x03)
        Timber.d("Lock bytes: ${otpPage.toHexString()}")
        Timber.d("Lock byte 1: ${(otpPage[0].toInt() and 0xFF).toString(2)}")
        Timber.d("Lock byte 2: ${(otpPage[1].toInt() and 0xFF).toString(2)}")

        val capabilityContainer = mifare.readPages(0x03).sliceArray(0 until 4)
        val ndefSizeByte = capabilityContainer[2]
        // More info: 8.5.4 Capability Container
        val ndefSize = when (ndefSizeByte) {
            0x12.toByte() -> 144
            0x3E.toByte() -> 496
            0x6D.toByte() -> 872
            else -> -1
        }
        Timber.d("NDEF size from CC: $ndefSize")

        mifare.close()
    }

    private fun onNdefDiscovered(ndef: Ndef) {
        Timber.d("Tag is NDEF")
        ndef.connect()

        val message = ndef.ndefMessage
        val records = message.records
        parseMessage(message)
        Timber.d("NDEF message contains ${records.size} records")
        for (p in records.withIndex()) {
            val record = p.value
            if (NdefRecord.RTD_SMART_POSTER.contentEquals(record.type)) {
                parseSmartPoster(record)
            } else {
                Timber.d("Unhandled RTD type: ${String(record.type)}")
            }
        }
        adapter.data = records.toList()
        adapter.notifyDataSetChanged()

        ndef.close()
    }

    private fun parseMessage(message: NdefMessage) {
        val data = message.toByteArray()
        var ptr = 0
        val header = data[ptr].toInt()
        val MB = (header shr 7) and 1
        val ME = (header ushr 6) and 1
        val CF = (header ushr 5) and 1
        val SR = (header ushr 4) and 1
        val IL = (header ushr 3) and 1
        val TNF = header and 0b00000111
        val typeLength = data[++ptr]
        val payloadLength: Int
        if (SR == 1) {
            payloadLength = data[++ptr].toInt()
            ptr++
        } else {
            payloadLength = data[ptr + 4].toInt() or data[ptr + 3].toInt() or data[ptr + 2].toInt() or data[ptr + 1].toInt()
            ptr += 4
        }
        val idLength: Byte
        if (IL == 1) {
            idLength = data[ptr++]
        } else {
            idLength = 0
        }
        val recordType = data[ptr++]
        val recordId: Byte
        if (idLength > 0) {
            // TODO assemble record id
        }
        val payload = Arrays.copyOfRange(data, ptr, ptr + payloadLength - 1)
        if (recordType == 84.toByte()) {
            // Is RTD_TEXT
            val statusByte = payload[0]
            val isUtf8 = (statusByte and 128.toByte()) == 0.toByte()
            val encoding = if (isUtf8) "UTF-8" else "UTF-16"
            val languageCodeLength = statusByte and 0b00011111
            val languageCode = String(payload, 1, languageCodeLength.toInt(), Charset.forName("US-ASCII"))
            val payloadString = String(payload, 1 + languageCodeLength, payload.size - 1 - languageCodeLength,
                    Charset.forName(encoding))
            val z = 4
        }
        val x = 4
    }

    private fun parseSmartPoster(record: NdefRecord) {
        Timber.d("Parsing record as Smart poster")
        val smartPosterContentMessage = NdefMessage(record.payload)
        val records = smartPosterContentMessage.records
        for (spRecord in records) {
            Timber.d("SP record: ${String(spRecord.type)}")
        }
    }

    override fun onResume() {
        super.onResume()

        if (!isInReadMode) {
            registerNfcForegroundDispatch()
        }
    }

    override fun onPause() {
        super.onPause()


        if (isFinishing && isInReadMode) {
            unregisterNfcForegroundDispatch()
        }
    }

    private fun registerNfcForegroundDispatch() {
        Timber.d("Registering NFC foreground dispatch")
        val discoveryFilter = IntentFilter()
        discoveryFilter.addAction(NfcAdapter.ACTION_TAG_DISCOVERED)
        val tagFilters = arrayOf(discoveryFilter)
        val i = Intent(this, javaClass)
                .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        val pi = PendingIntent.getActivity(this, 0, i, 0)
        nfcAdapter!!.enableForegroundDispatch(this, pi, tagFilters, null)
        isInReadMode = true
    }

    private fun unregisterNfcForegroundDispatch() {
        Timber.d("Unregistering NFC foreground dispatch")
        nfcAdapter!!.disableForegroundDispatch(this)
        isInReadMode = false
    }
}
