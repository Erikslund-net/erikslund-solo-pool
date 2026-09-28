#include "net/zmq_subscriber.hpp"

#include <zmq.h>

#include <cerrno>
#include <chrono>
#include <span>
#include <string>
#include <thread>
#include <utility>

#include "core/logging.hpp"
#include "util/hex.hpp"

namespace erikslund::net {

ZmqSubscriber::ZmqSubscriber(Pool& pool, std::string endpoint)
    : pool_(pool), endpoint_(std::move(endpoint)) {}

void ZmqSubscriber::run(const std::stop_token& stop) {
    void* context = zmq_ctx_new();
    void* socket = zmq_socket(context, ZMQ_SUB);

    // Timeout lets the loop poll the stop token instead of blocking.
    int timeout_ms = 500;
    zmq_setsockopt(socket, ZMQ_RCVTIMEO, &timeout_ms, sizeof(timeout_ms));

    if (zmq_connect(socket, endpoint_.c_str()) != 0) {
        log::warning("ZMQ: cannot connect to {} ({}); fast block notify disabled", endpoint_,
                     zmq_strerror(zmq_errno()));
        zmq_close(socket);
        zmq_ctx_term(context);
        return;
    }
    zmq_setsockopt(socket, ZMQ_SUBSCRIBE, "hashblock", 9);
    log::info("ZMQ: subscribed to hashblock at {}", endpoint_);

    // bitcoind sends [topic, 32-byte hash, sequence]. Frame 1 is the hash in
    // display (big-endian) order -> previousblockhash for fastblock work.
    int frame = 0;
    std::string hash_bytes;
    while (!stop.stop_requested()) {
        zmq_msg_t message;
        zmq_msg_init(&message);
        const int received = zmq_msg_recv(&message, socket, 0);
        if (received < 0) {
            zmq_msg_close(&message);
            frame = 0;
            hash_bytes.clear();
            const int error = zmq_errno();
            if (error == EAGAIN || error == EINTR)
                continue; // timeout/interrupted
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }

        if (frame == 1)
            hash_bytes.assign(static_cast<const char*>(zmq_msg_data(&message)), zmq_msg_size(&message));
        ++frame;

        int more = 0;
        size_t more_size = sizeof(more);
        zmq_getsockopt(socket, ZMQ_RCVMORE, &more, &more_size);
        zmq_msg_close(&message);
        if (more)
            continue;

        std::string hash_hex;
        if (hash_bytes.size() == 32)
            hash_hex = util::to_hex(std::span<const uint8_t>(
                reinterpret_cast<const uint8_t*>(hash_bytes.data()), hash_bytes.size()));
        frame = 0;
        hash_bytes.clear();
        pool_.on_zmq_block(hash_hex);
        log::info("ZMQ: new-block notification {}", hash_hex);
    }

    zmq_close(socket);
    zmq_ctx_term(context);
}

} // namespace erikslund::net
