#include <iostream>
#include <vector>
#include <windows.h>
#include <stringapiset.h>
#include <fcntl.h>
#include <io.h>

class LockedMem {
public:
	LockedMem(HANDLE hnd);
	~LockedMem();
	LPVOID Lock();
	void Unlock();
protected:
	bool is_locked;
	HANDLE h;
};

void LockedMem::Unlock() {
	if (is_locked) {
		GlobalUnlock(h);
	}
}

LockedMem::LockedMem(HANDLE hnd) {
	is_locked = false;
	h = hnd;
}

LPVOID LockedMem::Lock() {
	if (!is_locked) {
		auto res = GlobalLock(h);
		is_locked = (res != NULL);

		return res;
	} else {
		return NULL;
	}
}

LockedMem::~LockedMem(){
	Unlock();
}

class Clipboard {
public:
	Clipboard();
	bool open();
	bool get_clipboard_utf8(std::string& res);
	void close();

	static bool to_utf8(std::string& res);

	~Clipboard();	

protected:
	bool is_open;
};

bool Clipboard::to_utf8(std::string& res) {
	Clipboard clip;

	if (!clip.open()) {
		return false;
	}

	if (!clip.get_clipboard_utf8(res)) {
		return false;
	}

	return true;
}

void Clipboard::close() {
	if (is_open)
	{
		CloseClipboard();
	}
}

Clipboard::~Clipboard() {
	close();
}

Clipboard::Clipboard() {
	is_open = false;
}

// True on success
bool Clipboard::open() {
	auto res = OpenClipboard(NULL);
	is_open = res != 0;

	return is_open;
}

bool Clipboard::get_clipboard_utf8(std::string& res) {
	if (!is_open) {
		return false;
	}

	// https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getclipboarddata says:
	// The clipboard controls the handle that the GetClipboardData function returns, not the application. The 
	// application should copy the data immediately. The application **must not free the handle** nor leave it locked.	
	auto h = GetClipboardData(CF_UNICODETEXT);
	if (h == NULL) {
		return false;
	}

	auto mem = LockedMem(h);

	auto utf16_data = mem.Lock();
	if (utf16_data == NULL) {
		return false;
	}

	// determine output buffer size
	auto num_bytes_needed = WideCharToMultiByte(CP_UTF8, 0, (LPCWCH)utf16_data, -1, NULL, 0, NULL, NULL);
	if (num_bytes_needed == 0) {
		return false;
	}

	// convert to UTF-8
	std::vector<char> buf(num_bytes_needed);
	auto conv_res = WideCharToMultiByte(CP_UTF8, 0, (LPCWCH)utf16_data, -1, buf.data(), num_bytes_needed, NULL, NULL);
	if (conv_res == 0) {
		return false;
	}
	auto temp = std::string(buf.data());
	res = temp;

	// GlobalUnlock(h) is called by destructor of mem
	// see above: Not calling GlobalFree(h);	

	return true;
}

void help() {	
	std::cout << "usage: pasteprog.exe [-b] | [-t] | [-h]" << std::endl;
	std::cout << "       -b binary output (default)" << std::endl;
	std::cout << "       -t text output" << std::endl;
	std::cout << "       -h print help message" << std::endl;
	std::cout << std::endl;
	std::cout << "This program prints the contents of the clipboard as an UTF-8 encoded string to stdout." << std::endl;
}

bool parse_opts(int argc, char* argv[], bool& do_stop) {
	bool binary = true;

	if (argc > 1) {
		for (int i = 1; i < argc; i++) {
			std::string opt = std::string(argv[i]);

			if (opt == "-h") {
				help();
				do_stop = true;
			}
			else {
				if (opt == "-b") {
					binary = true;
				}
				else {
					if (opt == "-t") {
						binary = false;
					}
				}
			}
		}
	}

	return binary;
}

int main(int argc, char *argv[])
{
	auto clip_contents = std::string();
	bool do_stop = false;
	bool binary = parse_opts(argc, argv, do_stop);

	if (do_stop) {
		return 42;
	}

	if (!Clipboard::to_utf8(clip_contents)) {
		return 42;
	}

	if (binary) {
		(void)_setmode(_fileno(stdout), O_BINARY);
	}
	
    std::cout << clip_contents << std::endl;
	std::cout.flush();

	if (binary) {
		(void)_setmode(_fileno(stdout), O_TEXT);
	}
	
	return 0;
}
