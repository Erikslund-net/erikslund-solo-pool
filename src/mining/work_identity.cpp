#include "mining/work_identity.hpp"

#include <array>
#include <cerrno>
#include <charconv>
#include <format>
#include <limits>
#include <stdexcept>
#include <string>
#include <system_error>

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include "util/unique_fd.hpp"

namespace erikslund::mining {

namespace {

constexpr std::size_t kGenerationDigits = 20;

void check_io(int result, const std::filesystem::path& path) {
    if (result < 0)
        throw std::system_error(errno, std::generic_category(), path.string());
}

void sync_file(int descriptor, const std::filesystem::path& path) {
    int result;
    do {
        result = ::fsync(descriptor);
    } while (result < 0 && errno == EINTR);
    check_io(result, path);
}

uint64_t read_generation(const std::filesystem::path& path) {
    const util::UniqueFd file(::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    if (!file && errno == ENOENT)
        return 0;
    check_io(file.get(), path);
    struct stat status{};
    check_io(::fstat(file.get(), &status), path);
    if (!S_ISREG(status.st_mode) || status.st_size != kGenerationDigits + 1)
        throw std::runtime_error("Invalid work generation file: " + path.string());

    std::array<char, kGenerationDigits + 1> contents{};
    std::size_t position = 0;
    while (position < contents.size()) {
        const auto count = ::read(file.get(), contents.data() + position, contents.size() - position);
        if (count < 0 && errno == EINTR)
            continue;
        check_io(static_cast<int>(count), path);
        if (count == 0)
            throw std::runtime_error("Truncated work generation file: " + path.string());
        position += static_cast<std::size_t>(count);
    }
    uint64_t generation = 0;
    const auto [end, error] = std::from_chars(
        contents.data(), contents.data() + kGenerationDigits, generation);
    if (error != std::errc{} || end != contents.data() + kGenerationDigits ||
        contents.back() != '\n' || generation == 0)
        throw std::runtime_error("Invalid work generation file: " + path.string());
    return generation;
}

} // namespace

uint64_t reserve_work_generation(const std::filesystem::path& directory) {
    std::filesystem::create_directories(directory);
    const auto absolute_directory = std::filesystem::canonical(directory);
    const util::UniqueFd directory_descriptor(::open(absolute_directory.c_str(),
                                                    O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    check_io(directory_descriptor.get(), absolute_directory);
    const auto path = absolute_directory / "work-generation";
    const auto lock_path = absolute_directory / "work-generation.lock";
    // Lock a separate inode: replacing the state file must not release startup serialization.
    const util::UniqueFd lock(::open(lock_path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW,
                                     S_IRUSR | S_IWUSR));
    check_io(lock.get(), lock_path);
    int locked;
    do {
        locked = ::flock(lock.get(), LOCK_EX);
    } while (locked < 0 && errno == EINTR);
    check_io(locked, lock_path);

    const uint64_t previous = read_generation(path);
    if (previous == std::numeric_limits<uint64_t>::max())
        throw std::overflow_error("Work generation exhausted");
    if (previous == 0) {
        // Persist new ancestors, including another startup's mkdir, before publishing any generation.
        int result;
        do {
            result = ::syncfs(directory_descriptor.get());
        } while (result < 0 && errno == EINTR);
        check_io(result, absolute_directory);
    }
    const uint64_t generation = previous + 1;
    const auto temporary = absolute_directory / "work-generation.tmp";
    const util::UniqueFd output(::open(temporary.c_str(),
        O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, S_IRUSR | S_IWUSR));
    check_io(output.get(), temporary);
    const auto contents = std::format("{:020}\n", generation);
    std::size_t position = 0;
    while (position < contents.size()) {
        const auto count = ::write(output.get(), contents.data() + position, contents.size() - position);
        if (count < 0 && errno == EINTR)
            continue;
        check_io(static_cast<int>(count), temporary);
        if (count == 0)
            throw std::runtime_error("Short write: " + temporary.string());
        position += static_cast<std::size_t>(count);
    }
    sync_file(output.get(), temporary);
    std::filesystem::rename(temporary, path);
    sync_file(directory_descriptor.get(), absolute_directory);
    return generation;
}

} // namespace erikslund::mining
