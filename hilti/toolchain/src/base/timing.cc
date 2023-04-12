// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/base/logger.h>
#include <hilti/base/timing.h>
#include <hilti/base/util.h>

using namespace hilti::util;
using namespace hilti::util::timing;
using namespace hilti::util::timing::detail;

using hilti::util::fmt;

static std::string prettyTime(Duration d) {
    static const std::vector<std::pair<std::string, double>> units = {{"w ", 1e9 * 60 * 60 * 24 * 7},
                                                                      {"d ", 1e9 * 60 * 60 * 24},
                                                                      {"hr", 1e9 * 60 * 60},
                                                                      {"m ", 1e9 * 60},
                                                                      {"s ", 1e9},
                                                                      {"ms", 1e6},
                                                                      {"us", 1e3},
                                                                      {"ns", 1}};

    auto x = std::chrono::duration_cast<std::chrono::nanoseconds>(d);

    if ( x.count() == 0 )
        return "0s";

    for ( const auto& [unit, factor] : units ) {
        if ( static_cast<double>(x.count()) >= factor )
            return fmt("%.2f%s", static_cast<double>(x.count()) / factor, unit);
    }

    cannot_be_reached();
};

static std::string prettyTimeForUnit(Duration d, double factor, const std::string& unit) {
    auto x = std::chrono::duration_cast<std::chrono::nanoseconds>(d);
    return fmt("%.2f%s", static_cast<double>(x.count()) / factor, unit);
}

std::shared_ptr<Manager> Manager::singleton() {
    static std::shared_ptr<Manager> singleton;

    if ( ! singleton )
        singleton = std::shared_ptr<Manager>(new Manager());

    return singleton;
}

void Manager::register_(Ledger* ledger) {
    if ( _all_ledgers.find(ledger->name()) != _all_ledgers.end() )
        hilti::logger().internalError(fmt("ledger %s already exists", ledger->name()));

    _all_ledgers[ledger->name()] = ledger;
}


void Manager::unregister(Ledger* ledger) { _all_ledgers.erase(ledger->name()); }

Ledger* Manager::newLedger(const std::string& name) {
    if ( auto i = _all_ledgers.find(name); i != _all_ledgers.end() )
        return i->second;

    _our_ledgers.emplace_back(name);
    return &_our_ledgers.back();
}

void Manager::summary(std::ostream& out) {
    auto mgr = singleton();

    if ( mgr->_all_ledgers.empty() ) {
        out << "=== No timing information recorded." << std::endl;
        return;
    }

    std::list<Ledger*> sorted_ledgers;

    for ( const auto& [name, ledger] : mgr->_all_ledgers ) {
        if ( ledger->_num_completed == 0 )
            continue;

        sorted_ledgers.emplace_back(ledger);
    }

    sorted_ledgers.sort([](const auto& x, const auto& y) { return x->_time_used.count() > y->_time_used.count(); });

    auto total_time = (Clock::now() - mgr->_created);

    out << "\n=== Execution Time Summary ===\n\n";

    for ( auto ledger : sorted_ledgers )
        out << fmt("%7.2f%%  ",
                   (100 * static_cast<double>(ledger->_time_used.count()) / static_cast<double>(total_time.count())))
            << fmt("%8s", prettyTimeForUnit(ledger->_time_used, 1e9, "s")) << "   " << ledger->_name << " "
            << fmt("(#%" PRIu64 ")", ledger->_num_completed) << "\n";

    out << "\nTotal time: " << prettyTime(total_time) << "\n";
    out << std::endl;
}
