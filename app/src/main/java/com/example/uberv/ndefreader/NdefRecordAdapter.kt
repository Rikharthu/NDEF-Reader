package com.example.uberv.ndefreader

import android.nfc.NdefRecord
import android.support.v7.widget.RecyclerView
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import com.example.uberv.ndefreader.NdefRecordUtils.getTnfLabel
import com.example.uberv.ndefreader.NdefRecordUtils.getTypeLabel
import kotlinx.android.synthetic.main.ndef_record_list_item.view.*

class NdefRecordAdapter : RecyclerView.Adapter<NdefRecordAdapter.ViewHolder>() {

    var data: List<NdefRecord> = listOf()

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        return ViewHolder(LayoutInflater.from(parent.context)
                .inflate(R.layout.ndef_record_list_item, parent, false))
    }

    override fun getItemCount(): Int {
        return data.size
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val record = data[position]
        with(holder.itemView) {
            recordTypeDef.text = "${record.getTypeLabel()} (${String(record.type)}, ${record.type.toHexString()})"
            typeName.text = "${record.getTnfLabel()} (${record.tnf})"
            payload.text = String(record.payload)
        }
    }

    class ViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView)
}