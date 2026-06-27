#pragma once

namespace papa::engine {
class Statement;
}  // namespace papa::engine

namespace papa::rules {

// Reorder a rule's and/or/some children so cheaper, more selective features are
// evaluated first, a faithful port of capa's optimizer (capa/optimizer.py).
// Parity-neutral: the boolean match outcome is unchanged, only the evaluation
// order (and thus the short-circuit speed) and the rendered child order differ.
void optimize(engine::Statement& statement);

}  // namespace papa::rules
