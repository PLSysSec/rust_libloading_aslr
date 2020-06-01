
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <link.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

#include <sys/types.h>
#include <unistd.h>
#include <sys/mman.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <algorithm>
#include <map>
#include <vector>
#include <string>
#include <iostream>
#include <sstream>
#include <fstream>

#define CHECK(x) if (!(x)) { abort(); }

struct RangeLine {
    uint64_t start;
    uint64_t end;
    std::string flags;
    std::string path;
};

static uint64_t parseHex(std::string val) {
    uint64_t x;
    std::stringstream ss;
    ss << std::hex << val;
    ss >> x;
    return x;
}

static RangeLine parseLine(std::string line) {
    RangeLine ret;

    std::istringstream iss(line);

    std::string range;
    iss >> range;

    std::string::size_type pos = range.find('-');
    if(range.npos == pos) {
        abort();
    } else {
        ret.start = parseHex(range.substr(0, pos));
        ret.end = parseHex(range.substr(pos + 1));
    }

    iss >> ret.flags;

    std::string dummy;
    iss >> dummy;
    iss >> dummy;
    iss >> dummy;

    iss >> ret.path;
    // std::cout << "Substring: " << ret.start << std::endl;
    // std::cout << "Substring: " << ret.end << std::endl;
    // std::cout << "Substring: " << ret.flags << std::endl;
    // std::cout << "Substring: " << ret.path << std::endl;

    return ret;
}

 std::vector<RangeLine> loadRanges() {
    char command[256];
    sprintf(command, "/proc/%d/maps", getpid());
    std::ifstream file(command);

    std::vector<RangeLine> ranges;
    if (file.is_open()) {
        std::string line;
        while (std::getline(file, line))
        {
            auto ret = parseLine(line);
            if (ret.flags[0] == 'r') {
                ranges.emplace_back(ret);
            }
            else {
                int a = 1;
                (void)a;
            }
        }
        file.close();
    }

    return ranges;
}

struct Range {
    char* start;
    char* end;
};

struct LoadedLibInfo {
    void* originalLib;
    std::vector<Range> library_ranges;
};

std::map<std::string, LoadedLibInfo> libInfo;


struct ASLRLib {
    void* libBase;
    uint64_t length;
    void* originalLib;
    void* originalLibBase;
};

bool aslr_enabled = false;

extern "C"
{
__attribute__((weak))
 void aslr_load_library_info() {
    libInfo.clear();

    std::vector<RangeLine> ranges = loadRanges();
    for(auto& r : ranges){
        auto it = libInfo.find(r.path);

        if (it == libInfo.end()) {
            // see if we can load this lib
            void* originalLib = dlopen(r.path.c_str(), RTLD_NOW);
            if (!originalLib) {
                continue;
            }
            libInfo[r.path].originalLib = originalLib;
        }

        libInfo[r.path].library_ranges.emplace_back(Range{
            (char*) (uintptr_t) r.start,
            (char*) (uintptr_t) r.end
        });
    }

    for (auto& element : libInfo) {
        struct {
            bool operator()(Range& a, Range& b) const
            {
                if (a.start < b.start) {
                    return true;
                } else if (a.start > b.start) {
                    return false;
                }  else {
                    return a.end < b.end;
                }
            }
        } customCompare;

        std::sort(element.second.library_ranges.begin(), element.second.library_ranges.end(), customCompare);
    }
}

__attribute__((weak))
void aslr_dl_enable() {
    aslr_enabled = true;
}
__attribute__((weak))
void aslr_dl_disable() {
    aslr_enabled = false;
}


__attribute__((weak))
void* aslr_dlopen(const char* libName, int flag) {
    if (!aslr_enabled) {
        return dlopen(libName, flag);
    }
    auto it = libInfo.find(libName);
    if (it == libInfo.end()) {
        // forcibly load - use RTLD_NOW always, not sure how delayed load would work here
        (void) flag;
        void* lib = dlopen(libName, RTLD_NOW);
        if (!lib) {
            return nullptr;
        }
        aslr_load_library_info();
        it = libInfo.find(libName);
        if (it == libInfo.end()) {
            // still couldn't find the lib
            abort();
        }
    }

    auto& curr = it->second;
    std::vector<Range>& ranges = curr.library_ranges;
    char* start = ranges[0].start;
    char* end = ranges[ranges.size() - 1].end;
    auto total_size = end - start;

    // printf("total_size: %lu\n", (uint64_t)total_size);
    char* target = (char*) mmap(NULL, total_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (!target || target == MAP_FAILED) {
        abort();
    }

    for(auto& r : ranges) {
        uint64_t offset = r.start - start;
        uint64_t size = r.end - r.start;
        // printf("target + offset: %p\n", (void*)(target + offset));
        // printf("r.start: %p\n", (void*)(r.start));
        // printf("size: %lu\n", (uint64_t)(size));
        memcpy(target + offset, r.start, size);
    }

    auto ret = new ASLRLib;
    ret->libBase = target;
    ret->length = total_size;
    ret->originalLib = curr.originalLib;
    ret->originalLibBase = start;
    return ret;
}

__attribute__((weak))
int aslr_dlclose(ASLRLib* lib) {
    if (!aslr_enabled) {
        return dlclose(lib);
    }
    munmap(lib->libBase, lib->length);
    delete lib;
    return 0;
}

__attribute__((weak))
void* aslr_dlsym(ASLRLib* lib, const char *symbol) {
    if (!aslr_enabled) {
        return dlsym(lib, symbol);
    }

    void* sym = dlsym(lib->originalLib, symbol);
    if (!sym) {
        return sym;
    }
    auto address = ((char*) sym - (char*) lib->originalLibBase) + (char*) lib->libBase;
    return address;
}

}
