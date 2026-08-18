#pragma once

namespace papa::engine {
class Statement;
}  // namespace papa::engine

namespace papa::rules {

// Reorder a rule's and, or and some children so cheaper features are evaluated
// first, a faithful port of capa's optimizer. The match outcome is unchanged
void optimize(engine::Statement& statement);

}  // namespace papa::rules
