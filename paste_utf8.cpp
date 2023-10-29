#include <iostream>
#include <vector>
#include <windows.h>
#include <stringapiset.h>
#include <fcntl.h>
#include <io.h>

const int MAX_DATA_SIZE = 32768;

class LockedMem {
public:
	LockedMem(HANDLE hnd);
	void Release() { is_released = true; } 
	~LockedMem();
	LPVOID Lock();
	void Unlock();
protected:
	bool is_locked;
	bool is_released;
	HANDLE h;
};

void LockedMem::Unlock() 
{
	if (is_locked) 
	{
		GlobalUnlock(h);
		is_locked = false;
	}
}

LockedMem::LockedMem(HANDLE hnd) 
{
	is_locked = false;
	is_released = false;
	h = hnd;
}

LPVOID LockedMem::Lock() 
{
	if (!is_locked) 
	{
		auto res = GlobalLock(h);
		is_locked = (res != NULL);

		return res;
	} 
	else 
	{
		return NULL;
	}
}

LockedMem::~LockedMem()
{
	Unlock();

	if (!is_released)
	{
		GlobalFree(h);
	}	
}

class Clipboard {
public:
	Clipboard();
	bool open();
	bool get_clipboard_utf8(std::string& res);
	bool set_clipboard_utf8(std::string& txt);
	void close();

	static bool to_utf8(std::string& res);
	static bool from_utf8(std::string& data_in);

	~Clipboard();	

protected:
	bool is_open;
};

bool Clipboard::to_utf8(std::string& res) 
{
	Clipboard clip;

	if (!clip.open()) 
	{
		return false;
	}

	if (!clip.get_clipboard_utf8(res)) 
	{
		return false;
	}

	return true;
}

bool Clipboard::from_utf8(std::string& data_in)
{
	Clipboard clip;

	if (!clip.open()) 
	{
		return false;
	}

	if (!clip.set_clipboard_utf8(data_in)) 
	{
		return false;
	}

	return true;
}

void Clipboard::close() 
{
	if (is_open)
	{
		CloseClipboard();
		is_open = false;
	}
}

Clipboard::~Clipboard() 
{
	close();
}

Clipboard::Clipboard() 
{
	is_open = false;
}

// True on success
bool Clipboard::open() 
{
	if (!is_open)
	{
		auto res = OpenClipboard(NULL);
		is_open = res != 0;
	}

	return is_open;
}

bool Clipboard::set_clipboard_utf8(std::string& txt)
{
	if (!is_open) 
	{
		return false;
	}	

	// determine output buffer size in UTF-16 chars
	auto num_chars_needed = MultiByteToWideChar(CP_UTF8, 0, (LPCCH)txt.c_str(), -1, NULL, 0);
	if (num_chars_needed == 0) 
	{
		return false;
	}

	// calculate output buffer size in bytes
	int num_bytes_needed = 2 * num_chars_needed;
	std::string utf16_string(num_bytes_needed, 32);

	// Convert to UTF-16
	auto conv_res = MultiByteToWideChar(CP_UTF8, 0, (LPCCH)txt.c_str(), -1, (LPWSTR)utf16_string.c_str(), num_chars_needed);
	if (conv_res == 0)
	{
		return false;
	}

	auto mem_handle = GlobalAlloc(GMEM_MOVEABLE, num_bytes_needed); 
	if (mem_handle == NULL) 
	{ 
		return false; 
	}

	LockedMem mem(mem_handle);

	auto ptr = mem.Lock();
	if (ptr == NULL)
	{
		// GlobalFree is called by the destructor of mem
		return false;
	}

	std::memcpy(ptr, utf16_string.c_str(), num_bytes_needed);

	mem.Unlock();

	auto h = SetClipboardData(CF_UNICODETEXT, mem_handle); 
	if (h == NULL)
	{
		// GlobalFree is called by the destructor of mem
		return false;
	}

	// The memory handle is now owned by the system. We do therefore not call
	// GlobalFree()
	mem.Release();

	return true;
}

bool Clipboard::get_clipboard_utf8(std::string& res) {
	if (!is_open) 
	{
		return false;
	}

	// https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getclipboarddata says:
	// The clipboard controls the handle that the GetClipboardData function returns, not the application. The 
	// application should copy the data immediately. The application **must not free the handle** nor leave it locked.	
	auto h = GetClipboardData(CF_UNICODETEXT);
	if (h == NULL) 
	{
		return false;
	}

	auto mem = LockedMem(h);
	// We are not responsible for freeing the memory handle
	mem.Release();

	auto utf16_data = mem.Lock();
	if (utf16_data == NULL) 
	{
		return false;
	}

	// determine output buffer size
	auto num_bytes_needed = WideCharToMultiByte(CP_UTF8, 0, (LPCWCH)utf16_data, -1, NULL, 0, NULL, NULL);
	if (num_bytes_needed == 0) 
	{
		return false;
	}

	// convert to UTF-8
	std::vector<char> buf(num_bytes_needed);
	auto conv_res = WideCharToMultiByte(CP_UTF8, 0, (LPCWCH)utf16_data, -1, buf.data(), num_bytes_needed, NULL, NULL);
	if (conv_res == 0) 
	{
		return false;
	}
	auto temp = std::string(buf.data());
	res = temp;

	// GlobalUnlock(h) is called by destructor of mem
	// see above: Not calling GlobalFree(h);	

	return true;
}

void help() {	
	std::cout << "usage: paste_utf8.exe [-b] | [-t] | [-h] | [-c]" << std::endl;
	std::cout << "       -b read/write in binary mode (default)" << std::endl;
	std::cout << "       -t read/write in text mode" << std::endl;
	std::cout << "       -c copy stdin to clipbpoard" << std::endl;
	std::cout << "       -h print help message" << std::endl;
	std::cout << std::endl;
	std::cout << "This program prints the contents of the clipboard as an UTF-8 encoded string to stdout." << std::endl;
	std::cout << "If the -c option is specified paste_utf8.exe copies data from stdin to the clipboard." << std::endl;
}

bool parse_opts(int argc, char* argv[], bool& do_stop, bool& do_copy) {
	bool binary = true;
	do_copy = false;
	do_stop = false;

	if (argc > 1) 
	{
		for (int i = 1; i < argc; i++) 
		{
			std::string opt = std::string(argv[i]);

			if (opt == "-h") 
			{
				help();
				do_stop = true;
			}
			else 
			{
				if (opt == "-b") 
				{
					binary = true;
				}
				
				if (opt == "-t") 
				{
					binary = false;
				} 

				if (opt == "-c") 
				{
					do_copy = true;
				}
			}
		}
	}

	return binary;
}

int paste_clipboard(bool binary) 
{
	auto clip_contents = std::string();

	if (!Clipboard::to_utf8(clip_contents)) 
	{
		return 42;
	}

	if (binary) 
	{
		(void)_setmode(_fileno(stdout), O_BINARY);
	}
	
    std::cout << clip_contents << std::endl;
	std::cout.flush();

	if (binary) 
	{
		(void)_setmode(_fileno(stdout), O_TEXT);
	}

	return 0;
}

int read_stdin(bool binary, std::vector<char>& data)
{
	int  res = 0;

	// yes I know, this can also be controlled from std::iostream
	if (binary) 
	{
		(void)_setmode(_fileno(stdin), O_BINARY);
	}

	try
	{
		std::cin.read(data.data(), data.size());
		// if eof is not set we either have data which is too long or
		// reading from cin failed. Here both cases are considered an 
		// error.
		if (!std::cin.eof())
		{
			// Goto end ;-)
			throw 42;
		}

		res = static_cast<int>(std::cin.gcount());
	}
	catch(...)
	{
		res = -1;
	}

	if (binary) {
		(void)_setmode(_fileno(stdin), O_TEXT);
	}

	return res;
}

int set_clipboard(bool binary, std::vector<char>& data)
{
	Clipboard clip;

	auto data_len = read_stdin(binary, data);
	if (data_len < 0)
	{
		return 42;
	}

	std::string utf8_string(data.data(), data_len);

	if (!Clipboard::from_utf8(utf8_string))
	{
		return 42;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	bool do_copy;
	bool do_stop = false;
	bool binary = parse_opts(argc, argv, do_stop, do_copy);
	int res;
	std::vector<char> data(MAX_DATA_SIZE, 0);

	if (do_stop) 
	{
		return 42;
	}

	if (!do_copy)
	{
		res = paste_clipboard(binary);
	}
	else
	{
		res = set_clipboard(binary, data);
	}

	return res;
}
