//===-- Statistics.cpp ----------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "klee/Statistics.h"

#include <vector>

using namespace klee;

StatisticManager::StatisticManager()
  : enabled(true),
    globalStats(nullptr),
    indexedStats(nullptr),
    contextStats(nullptr),
    index(0) {}

void StatisticManager::useIndexedStats(unsigned totalIndices) {  
  indexedStats.reset(new uint64_t[totalIndices * stats.size()]);
  memset(indexedStats.get(), 0, sizeof(indexedStats[0]) * totalIndices * stats.size());
}

void StatisticManager::registerStatistic(Statistic &s) {
  s.id = static_cast<unsigned>(stats.size());
  stats.push_back(&s);
  globalStats.reset(new uint64_t[stats.size()]);
  memset(globalStats.get(), 0, sizeof(globalStats[0])*stats.size());
}

int StatisticManager::getStatisticID(const std::string &name) const {
  for (unsigned i=0; i < stats.size(); i++) {
    if (stats[i]->getName() == name) {
      return static_cast<int>(i);
    }
  }
  return -1;
}

Statistic *StatisticManager::getStatisticByName(const std::string &name) const {
  for (unsigned i=0; i<stats.size(); i++)
    if (stats[i]->getName() == name)
      return stats[i];
  return 0;
}

StatisticManager *klee::theStatisticManager = 0;

static StatisticManager &getStatisticManager() {
  static StatisticManager sm;
  theStatisticManager = &sm;
  return sm;
}

/* *** */

Statistic::Statistic(const std::string &_name, 
                     const std::string &_shortName) 
  : id(0),
    name(_name),
    shortName(_shortName) {
  getStatisticManager().registerStatistic(*this);
}

Statistic::~Statistic() {
}

Statistic &Statistic::operator +=(const uint64_t addend) {
  theStatisticManager->incrementStatistic(*this, addend);
  return *this;
}

uint64_t Statistic::getValue() const {
  return theStatisticManager->getValue(*this);
}
