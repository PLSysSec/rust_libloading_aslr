
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

// Hack for mozilla code. Firefox wraps standard libs but does not include the libs when linking rust packages
// So disable this for now.
#define mozilla_mozalloc_h
#define mozilla_throw_gcc_h
#define mozilla_mozalloc_abort_h

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
#include <random>
#include <string>
#include <iostream>
#include <sstream>
#include <fstream>
#include <mutex>
#include <shared_mutex>

struct RangeLine {
    bool found;
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

// A line looks like the following
// 7f906d9aa000-7f906db91000 r-xp 00000000 103:01 13272328                  /lib/x86_64-linux-gnu/libc-2.27.so
static RangeLine parseLine(std::string line) {
    RangeLine ret;

    std::istringstream iss(line);

    std::string range;
    iss >> range;

    std::string::size_type pos = range.find('-');
    if(range.npos == pos) {
        ret.found = false;
        return ret;
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
    ret.found = true;
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
            if (ret.found && ret.flags[0] == 'r') {
                ranges.emplace_back(ret);
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
std::shared_mutex mutex_libInfo;

// A marker to separate a regular library from an ASLR lib
const uint64_t ASLR_MARKER = 0xdeadbeefdeadbeef;

struct ASLRLib {
    uint64_t alsr_marker;
    void* libBase;
    uint32_t offset;
    uint64_t length;
    void* originalLib;
    void* originalLibBase;
};

bool aslr_enabled = false;

extern "C"
{
__attribute__((weak))
 void aslr_load_library_info() {
    std::vector<RangeLine> ranges = loadRanges();

    std::unique_lock lock(mutex_libInfo);
    libInfo.clear();
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

#define PAGE_SIZE (4 * 1024)
static std::random_device dev;
static std::mt19937 rng(dev());
static std::uniform_int_distribution<std::mt19937::result_type> dist(0, (PAGE_SIZE/16) - 1);


__attribute__((weak))
void* aslr_dlopen(const char* libName, int flag, bool aslr_enabled) {
    if (!aslr_enabled) {
        return dlopen(libName, flag);
    }

    std::shared_lock lock(mutex_libInfo);
    auto it = libInfo.find(libName);
    if (it == libInfo.end()) {
        // forcibly load - use RTLD_NOW always, not sure how delayed load would work here
        (void) flag;
        void* lib = dlopen(libName, RTLD_NOW);
        if (!lib) {
            return nullptr;
        }
        lock.unlock();
        aslr_load_library_info();
        lock.lock();

        it = libInfo.find(libName);
        if (it == libInfo.end()) {
            // still couldn't find the lib
            return nullptr;
        }
    }

    auto& curr = it->second;
    std::vector<Range>& ranges = curr.library_ranges;
    char* start = ranges[0].start;
    char* end = ranges[ranges.size() - 1].end;
    size_t total_size = end - start;

    // we are also going to copy pages starting at a random offset in the page
    // so add one extra page to catch the spill overs
    total_size += PAGE_SIZE;

    // we want an alignment of 16, so we pick a value between 0 and PAGE_SIZE/16 and multiply by 16
    uint32_t chosen_page_offset = dist(rng) * 16;

    // printf("total_size: %lu\n", (uint64_t)total_size);
    char* target = (char*) mmap(NULL, total_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (!target || target == MAP_FAILED) {
        return nullptr;
    }

    for(auto& r : ranges) {
        uint64_t offset = r.start - start + chosen_page_offset;
        uint64_t size = r.end - r.start;
        // printf("target + offset: %p\n", (void*)(target + offset));
        // printf("r.start: %p\n", (void*)(r.start));
        // printf("size: %lu\n", (uint64_t)(size));
        memcpy(target + offset, r.start, size);
    }

    auto ret = new ASLRLib;
    ret->alsr_marker = ASLR_MARKER;
    ret->libBase = target;
    ret->offset = chosen_page_offset;
    ret->length = total_size;
    ret->originalLib = curr.originalLib;
    ret->originalLibBase = start;
    return ret;
}

bool is_aslr_lib(ASLRLib* lib) {
    return lib->alsr_marker == ASLR_MARKER;
}

__attribute__((weak))
int aslr_dlclose(ASLRLib* lib) {
    if (!is_aslr_lib(lib)) {
        return dlclose(lib);
    }
    munmap(lib->libBase, lib->length);
    delete lib;
    return 0;
}

__attribute__((weak))
void* aslr_dlsym(ASLRLib* lib, const char *symbol) {
    if (!is_aslr_lib(lib)) {
        return dlsym(lib, symbol);
    }

    void* sym = dlsym(lib->originalLib, symbol);
    if (!sym) {
        return sym;
    }
    auto address = ((char*) sym - (char*) lib->originalLibBase) + (char*) lib->libBase + lib->offset;
    return address;
}

}
