/*
 * Copyright (C) 2017
 * SUSE Linux GmbH
 * Matthias Gerstner <matthias.gerstner@suse.com>
 */

// C++
#include <iomanip>
#include <ostream>

// ima-inspect
#include "ima_helpers.hxx"

std::ostream& operator<<(std::ostream &o, const HexDumpData &data)
{
	const auto backup_flags = o.flags();
	o << std::setfill('0');

	const auto num_bytes = data.getNumBytes();
	const auto datap = data.getData();

	for( size_t byte = 0; byte < num_bytes; byte++ )
	{
		o << std::setw(2) << std::hex << (size_t)datap[byte];

		// add a newline each 64 bytes
		if( (byte & (0x40 -1)) == (0x40 -1) )
		{
			o << "\n";
		}
		// add a space each 8 bytes
		else if( (byte & (0x8 -1)) == (0x8 -1) )
		{
			o << " ";
		}
	}

	o.flags( backup_flags );

	return o;
}

