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

protected: // data

	int m_res = 0;
	//! holds the currently handled xattr value
	std::vector<char> m_attr_data;

	// the xattr names to inspect per file
	static const std::array<std::string, 2> m_attr_names;

	// command line parsing
	TCLAP::CmdLine m_cmdline;
	TCLAP::UnlabeledMultiArg<std::string> m_arg_files;
};

#endif // inc. guard

