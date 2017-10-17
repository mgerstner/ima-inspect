/*
 * Copyright (C) 2017
 * SUSE Linux GmbH
 * Matthias Gerstner <matthias.gerstner@suse.com>
 */

#ifndef IMA_INSPECT_HXX
#define IMA_INSPECT_HXX

// third-party
#include <tclap/CmdLine.h>

class ImaInspect
{
public: // functions

	ImaInspect();

	void parseArgs(const int argc, const char **argv);

	void run();

protected: // data

	TCLAP::CmdLine m_cmdline;
	TCLAP::UnlabeledMultiArg<std::string> m_arg_files;
};

#endif // inc. guard

