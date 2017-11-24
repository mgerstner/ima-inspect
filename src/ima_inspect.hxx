/*
 * Copyright (C) 2017
 * SUSE Linux GmbH
 * Matthias Gerstner <matthias.gerstner@suse.com>
 */

#ifndef IMA_INSPECT_HXX
#define IMA_INSPECT_HXX

// C++
#include <array>
#include <iostream>
#include <fstream>

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

	//! returns whether we should skip display of the given attribute
	bool skipAttr(const std::string &attr);

	void setupNullOut();

	//! returns the output stream for human readable output
	std::ostream& getOutstream() const { return *m_outstream; }

	/**
	 * \brief
	 * 	Dumps the given data area according to m_arg_output
	 **/
	void dumpData(const uint8_t *p, const size_t bytes) const;

protected: // data

	mutable int m_res = 0;
	//! holds the currently handled xattr value
	std::vector<char> m_attr_data;
	//! how much bytes are left unprocessed in the current m_attr_data
	mutable size_t m_attr_data_left = 0;

	// the xattr names to inspect per file
	static const std::array<std::string, 2> m_attr_names;

	//! where regular messages should be written to
	mutable std::ostream *m_outstream = nullptr;
	//! an output stream ending up in /dev/null
	std::fstream m_null_dev;
	//! cached converted value for m_arg_output
	bool m_dump_as_binary = false;

	// command line parsing
	TCLAP::CmdLine m_cmdline;
	TCLAP::ValueArg<std::string> m_arg_attr;
	TCLAP::ValueArg<std::string> m_arg_output;
	TCLAP::UnlabeledMultiArg<std::string> m_arg_files;
};

#endif // inc. guard

