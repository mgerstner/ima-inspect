/*
 * Copyright (C) 2017
 * SUSE Linux GmbH
 * Matthias Gerstner <matthias.gerstner@suse.com>
 */

#ifndef IMA_INSPECT_HXX
#define IMA_INSPECT_HXX

// C++
#include <array>

// third-party
#include <tclap/CmdLine.h>

class ImaInspect
{
public: // functions

	ImaInspect();

	void parseArgs(const int argc, const char **argv);

	void run();

	int getRes() const { return m_res; }

protected: // functions

	void inspectFile(const std::string &path);

	bool getAttr(int fd, const std::string &attr);

	void inspectAttr() const;

	void inspectDigsig() const;
	void inspectDigsigV1() const;
	void inspectDigsigV2() const;

	void inspectDigest() const;
	void inspectDigestNg() const;

	void inspectHmac() const;

	/*
	 * bit fiddling functions
	 */

	const char* nextData() const {
		const auto parse_pos = m_attr_data.size() - m_attr_data_left;
		return & m_attr_data.at(parse_pos);
	}

	void recordDataConsumed(const size_t bytes) const
	{
		m_attr_data_left -= bytes;
	}

	const char* fetchNextData(const size_t bytes, const char *item) const;

	template<typename T>
	void fetchNextType(T*& out_ptr, const char *label) const;

	void assertDataLeft(const size_t bytes, const char *purpose) const;

protected: // data

	int m_res = 0;
	//! holds the currently handled xattr value
	std::vector<char> m_attr_data;
	//! how much bytes are left unprocessed in the current m_attr_data
	mutable size_t m_attr_data_left = 0;

	// the xattr names to inspect per file
	static const std::array<std::string, 2> m_attr_names;

	// command line parsing
	TCLAP::CmdLine m_cmdline;
	TCLAP::UnlabeledMultiArg<std::string> m_arg_files;
};

#endif // inc. guard

