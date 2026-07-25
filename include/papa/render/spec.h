#pragma once

#include <string>
#include <vector>

namespace papa::render {

// An ATT&CK reference parsed from a rule's "att&ck:" string, mirroring capa's
// AttackSpec (capa/render/result_document.py)
struct AttackSpec {
    std::vector<std::string> parts;
    std::string              tactic;
    std::string              technique;
    std::string              subtechnique;
    std::string              id;
};

// An MBC reference parsed from a rule's "mbc:" string, mirroring capa's MBCSpec
struct MbcSpec {
    std::vector<std::string> parts;
    std::string              objective;
    std::string              behavior;
    std::string              method;
    std::string              id;
};

// Parse "Tactic::Technique[::Subtechnique] [id]" into an AttackSpec
[[nodiscard]] AttackSpec attack_from_string(const std::string& s);

// Parse "Objective::Behavior[::Method] [id]" into an MbcSpec
[[nodiscard]] MbcSpec mbc_from_string(const std::string& s);

}  // namespace papa::render
