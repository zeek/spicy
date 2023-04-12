// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

/** API to measure execution times and frequency for code area. */

#pragma once

#include <cassert>
#include <chrono>
#include <list>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>

namespace hilti::util::timing {

using Clock = std::chrono::high_resolution_clock;
using Time = Clock::time_point;
using Duration = Clock::duration;

class Collector;
class Ledger;

namespace detail {

/** Singleton object managing all timer state. */
class Manager {
public:
    /**
     * Renders a summary of execution statistics for all currently existing
     * `Ledger` objects.
     */
    static void summary(std::ostream& out);

    /**
     * Returns a pointer to a global singleon manager instance. This returns
     * a shared_ptr so that ledgers can store that to ensure the global
     * singleton doesn't get destroyed at exit before they go away, too.
     */
    static std::shared_ptr<Manager> singleton();

protected:
    friend Collector;
    friend Ledger;

    Manager() : _created(Clock::now()) {}

    void register_(Ledger* ledger);
    void unregister(Ledger* ledger);
    Ledger* newLedger(const std::string& name);

private:
    Time _created;
    std::unordered_map<std::string, Ledger*> _all_ledgers;
    std::list<Ledger> _our_ledgers;
};

} // namespace detail

inline void summary(std::ostream& out) { detail::Manager::summary(out); }

/** Maintains measurements of execution time and frequency for one code area. */
class Ledger {
public:
    Ledger(std::string name) : _name(std::move(name)), _manager(detail::Manager::singleton()) {
        _manager->register_(this);
    }
    ~Ledger() { _manager->unregister(this); }

    Ledger() = delete;
    Ledger(const Ledger&) = default;
    Ledger(Ledger&&) noexcept = default;
    Ledger& operator=(const Ledger&) = delete;
    Ledger& operator=(Ledger&&) noexcept = delete;

    const std::string& name() const { return _name; }

    void summary(std::ostream& out) const;

protected:
    friend class Collector;
    friend class detail::Manager;

    void start() {
        if ( _level < 0 )
            return;

        if ( ++_level != 1 )
            return;

        assert(_time_started == Time());
        _time_started = Clock::now();
    }

    void stop() {
        if ( _level < 0 )
            return;

        assert(_level > 0);

        if ( --_level != 0 )
            return;

        assert(_time_started != Time());
        _time_used += (Clock::now() - _time_started);
        _time_started = Time();
        ++_num_completed;
    }

    void finish() {
        if ( _level > 0 ) {
            _time_used += (Clock::now() - _time_started);
            _time_started = Time();
            ++_num_completed;
        }

        _level = -1;
    }

    Duration _time_used = Duration(0);
    uint64_t _num_completed = 0;
    int64_t _level = 0;
    std::string _name;

private:
    std::shared_ptr<detail::Manager> _manager;
    Time _time_started;
};

/** Measure a code block's execution during its life-time. */
class Collector {
public:
    Collector(Ledger* ledger) : _ledger(ledger) { ledger->start(); }

    Collector(const std::string& name) {
        _ledger = detail::Manager::singleton()->newLedger(name);
        _ledger->start();
    }

    ~Collector() { _ledger->stop(); }

    void finish() { _ledger->finish(); }

    Collector() = delete;
    Collector(const Collector&) = delete;
    Collector(Collector&&) noexcept = delete;
    Collector& operator=(const Collector&) = delete;
    Collector& operator=(Collector&&) noexcept = delete;

protected:
    Ledger* _ledger;
};

} // namespace hilti::util::timing
