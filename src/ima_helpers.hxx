/*
 * Copyright (C) 2017
 * SUSE Linux GmbH
 * Matthias Gerstner <matthias.gerstner@suse.com>
 */

#ifndef IMA_HELPERS_HXX
#define IMA_HELPERS_HXX

// C++
#include <iosfwd>

//! helper type for producing hex dumps of arbitrary binary data
class HexDumpData
{
public:
	HexDumpData(const uint8_t *data, size_t bytes)
		: m_data(data), m_bytes(bytes)
	{}

	const uint8_t* getData() const { return m_data; }
	size_t getNumBytes() const { return m_bytes; }

protected: // data

	const uint8_t *m_data;
	size_t m_bytes;
};

std::ostream& operator<<(std::ostream &o, const HexDumpData &data);

#endif // inc. guard

