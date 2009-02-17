module PacketFu


	# PcapHeader describes the libpcap file header format, and is used in PcapFile.
	class PcapHeader < BinData::MultiValue
		endian	PacketFu.instance_variable_get("@byte_order")
		uint32			:magic,			:initial_value => 0xa1b2c3d4
		uint16			:ver_major,	:initial_value =>	2 
		uint16			:ver_minor,	:initial_value => 4
		int32				:thiszone,	:initial_value => 0
		uint32			:sigfigs,		:initial_value => 0
		uint32			:snaplen,		:initial_value => 0xffff
		uint32			:network,		:initial_value => 1
	end

	class Timestamp < BinData::MultiValue
		endian	PacketFu.instance_variable_get("@byte_order")
		uint32	:sec
		uint32	:usec
	end

	# PcapPacket describes a complete libpcap-formatted packet, which includes timestamp
	# and length information. It is used in PcapPackets class.
	class PcapPacket < BinData::MultiValue
		endian			PacketFu.instance_variable_get("@byte_order")
		timestamp		:timestamp
		uint32			:incl_len,	:value => lambda {data.length}
		uint32			:orig_len	
		string			:data,		:read_length => :incl_len
	end

	# PcapPackets is an BinData array type, used to collect packets and their associated
	# frame data. It is part of the PcapFile class. Sadly, I cannot pass an endianness for
	# and array type, so I need one of each.
	
	class PcapPackets < BinData::MultiValue
		array 		:data, :type => :pcap_packet, :read_until => :eof
	end

	# PcapFile is a complete libpcap file struct, made up of a PcapHeader and PcapPackets.
	#
	# See http://wiki.wireshark.org/Development/LibpcapFileFormat
	class PcapFile < BinData::MultiValue
		pcap_header			:head
		pcap_packets		:body
	end

end
