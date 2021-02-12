module PE;

export {

	type ExportName: record {
		rva:  count;
		name: string &optional;
	};

	type ExportAddress: record {
		rva:       count;
		forwarder: string &optional;
	};

	type ExportTable: record {
		flags:               count;
		timestamp:           time;
		major_version:       count;
		minor_version:       count;
		dll_name_rva:        count;
		ordinal_base:        count;
		address_table_count: count;
		name_table_count:    count;
		address_table_rva:   count;
		name_table_rva:      count;
		ordinal_table_rva:   count;
		dll:                 string &optional;
		addresses:           vector of ExportAddress &optional;
		names:               vector of ExportName &optional;
		ordinals:            vector of count &optional;
	};

	type Import: record {
		hint_name_rva: count &optional;
		hint:          count &optional;
		name:          string &optional;
		ordinal:       count &optional;
	};

	type ImportTableEntry: record {
		import_lookup_table_rva:  count;
		timestamp:                time;
		forwarder_chain:          count;
		dll_rva:                  count;
		import_address_table_rva: count;
		dll:                      string &optional;
		imports:                  vector of Import &optional;
	};

	type ImportTable: record {
		entries: vector of ImportTableEntry;
	};

}
