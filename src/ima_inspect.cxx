// C++
#include <iostream>
#include <memory>

// Linux
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
// contains a few more preprocessor defines than sys/xattr.h
#include <attr/xattr.h>

// ima-inspect
#include "ima_inspect.hxx"
#include "ima_exceptions.hxx"

// ima-evm-utils
#include "imaevm.h"

const std::array<std::string, 2> ImaInspect::m_attr_names = {
	"security.ima",
	"security.evm"
};

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
		try
		{
			std::cout << file << "\n\n";
			inspectFile(file);
		}
		catch( const std::exception &ex )
		{
			std::cerr << ex.what() << std::endl;
			m_res = 2;
		}
	}
}

void ImaInspect::inspectFile(const std::string &path)
{
	auto fd = open(path.c_str(), O_RDONLY | O_NOFOLLOW);

	if( fd == -1 )
	{
		throw SysError("open");
	}

	for( const auto &attr: m_attr_names )
	{
		try
		{
			std::cout << attr << ": ";
			bool have_attr = getAttr(fd, attr);

			if( !have_attr )
				continue;

			inspectAttr();
		}
		catch( const std::exception &ex )
		{
			std::cerr << ex.what() << std::endl;
			m_res = 2;
		}
	}

	close(fd);
}

void ImaInspect::inspectAttr() const
{
	const auto type = static_cast<enum evm_ima_xattr_type>(
		m_attr_data.at(0)
	);

	switch(type)
	{
	case IMA_XATTR_DIGEST:
		//inspectDigest();
		break;
	case IMA_XATTR_DIGEST_NG:
		//inspectDigestNg();
		break;
	case EVM_XATTR_HMAC:
		//inspectHmac();
		break;
	case EVM_IMA_XATTR_DIGSIG:
		inspectDigsig();
		break;
	default:
		std::cout << "unknown IMA/EVM attribute tagged with "
			<< static_cast<int>(type) << std::endl;
		break;
	}
}

void ImaInspect::inspectDigsig() const
{
	std::cout << "digital signature" << std::endl;
}

bool ImaInspect::getAttr(int fd, const std::string &attr)
{
	m_attr_data.clear();
	int res = -1;

	while( true )
	{
		res = fgetxattr(
			fd,
			attr.c_str(),
			m_attr_data.data(),
			m_attr_data.size()
		);

		if( res == -1 )
		{
			if( errno == ERANGE )
			{
				// re-calculate required space
				m_attr_data.clear();
				continue;
			}
			else if( errno == ENOATTR )
			{
				std::cout << "no such attribute\n";
				// no attribute
				return false;
			}

			throw SysError("fgetxattr");
		}
		else if( m_attr_data.empty() )
		{
			const auto length = static_cast<size_t>(res);
			m_attr_data.resize(length);
		}
		else
		{
			break;
		}
	}

	return true;
}

int main(const int argc, const char **argv)
{
	try
	{
		ImaInspect ima_inspect;
		ima_inspect.parseArgs(argc, argv);
		ima_inspect.run();
		return ima_inspect.getRes();
	}
	catch( const std::exception &ex )
	{
		std::cerr << "Failed: " << ex.what() << std::endl;
		return 1;
	}
}

