// C++
#include <iostream>

// Linux
#include <sys/xattr.h>

// ima-inspect
#include "ima_inspect.hxx"
#include "ima_exceptions.hxx"

ImaInspect::ImaInspect() :
	m_cmdline("This utility allows to display security.ima and "
		"security.evm extended attributes created by the "
		"'evmctl' utility from ima-evm-utils."),
	m_arg_files("files", "one or more files to inspect", true, "path",
		m_cmdline)
{
}

void ImaInspect::parseArgs(const int argc, const char **argv)
{
	m_cmdline.parse(argc, argv);
}

void ImaInspect::run()
{
	for( const auto &file: m_arg_files.getValue() )
	{
		std::cout << file << std::endl;
	}
}

int main(const int argc, const char **argv)
{
	try
	{
		ImaInspect ima_inspect;
		ima_inspect.parseArgs(argc, argv);
		ima_inspect.run();
		return 0;
	}
	catch( const std::exception &ex )
	{
		std::cerr << "Failed: " << ex.what() << std::endl;
	}

	return 0;
}

